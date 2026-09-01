"""
server.py
Author: Aditya Raj
Description:
    This file is the Central Hub of the Reliable Group Notification System.
    Why does this file exist?
    A system is only as fast as its slowest link. If clients had to do heavy math, 
    their devices would slow down. We made the server "stateful" so it handles 
    all the heavy lifting. It manages the expensive SSL Keys, keeps track of who 
    is offline, manages retransmissions, and aggressively broadcasts data.

    ── Hybrid Architecture Design ───────────────────────────────────────────────
    The server runs TWO network channels simultaneously:

    1. SSL/TCP Authentication Channel (Port 5001)
       - Uses military-grade TLS 1.3 encryption via built-in Python ssl library.
       - Solely exists to securely receive a client's SUBSCRIBE packet.
       - The moment a client subscribes, the server closes this TCP connection.

    2. UDP Data Channel (Port 5000)
       - Handles the massive volume of NOTIFY broadcasts and incoming ACKs.
       - Handles the heartbeat pings from clients.
       - Because the primary data traffic is UDP, the system is fundamentally UDP-based.

    ── Reliability Engineering (Garbage Collection) ─────────────────────────────
    How do we make UDP reliable?
    1. The server stores un-acknowledged packets in memory. If 2 seconds pass 
       without an ACK, it violently re-transmits the UDP datagram (max 3 times).
    2. If a client fails to send a HEARTBEAT ping within 5 seconds, the server 
       assumes their Wi-Fi died and automatically evicts them from the subscriber list.
"""

import socket     # Built-in network socket interface
import ssl        # Built-in cryptographic library to wrap sockets into TLS 1.3 tunnels
import threading  # Allows multiple loops to run in parallel without freezing the server
import time       # Used for measuring latency timestamps and timeout intervals
import logging    # Used for clean, professional console output
import random     # Used to artificially simulate packet loss during test metrics

# Import our universal binary language dictionary and network tools
from protocol import (
    TYPE_SUBSCRIBE, TYPE_NOTIFY, TYPE_ACK,
    TYPE_UNSUBSCRIBE, TYPE_HEARTBEAT,
    encode_packet, decode_packet, recv_packet
)

# ─── Server Configuration Constants ──────────────────────────────────────────
SERVER_IP       = "0.0.0.0"   # Binds to all available network interfaces (Localhost and Wi-Fi IP)
SERVER_UDP_PORT = 5000        # The megaphone port (Used for UDP blasting and ACKs)
SERVER_SSL_PORT = 5001        # The secure VIP door (Used only for TCP/SSL handshakes)

# ─── Security Payload (TLS) ──────────────────────────────────────────────────
SSL_CERT = "server.crt"   # Public Certificate (Sent down to verifying clients)
SSL_KEY  = "server.key"   # Private Key (Highly secret, kept strictly on the server)

# Hard limit for string length to prevent users from crashing the server
MAX_MESSAGE_LENGTH = 1000

# Configure logger output format
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger("Hybrid_Server")


class NotificationServer:
    def __init__(self, host=SERVER_IP, udp_port=SERVER_UDP_PORT,
                 ssl_port=SERVER_SSL_PORT, loss_rate=0.0):
        self.server_host = host
        self.server_addr = (host, udp_port)

        # ─── 1. Create the UDP Socket (The Postbox) ──────────────────────────
        # AF_INET = IPv4 Internet. SOCK_DGRAM = Connectionless UDP Datagram.
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # SO_REUSEADDR prevents the "OS Port Block" error if we restart the script too fast
        self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp_socket.bind((host, udp_port))
        logger.info(f"UDP data channel ready on port {udp_port}")

        # ─── 2. Create the SSL/TCP Socket (The VIP Door) ─────────────────────
        # PROTOCOL_TLS_SERVER auto-negotiates the highest security possible (TLS 1.3)
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            # Load the cryptographic keys from our workspace directory
            self.ssl_context.load_cert_chain(certfile=SSL_CERT, keyfile=SSL_KEY)
        except FileNotFoundError:
            logger.critical("SSL keys (server.crt/server.key) not found! Run the OpenSSL generation command.")
            raise

        # Setup standard TCP stream socket
        raw_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_tcp.bind((host, ssl_port))
        raw_tcp.listen(10)  # Put 10 clients in a queue if they connect at the exact same millisecond
        
        # Magic Line: Forcefully wrap the raw TCP socket in the SSL context!
        # Now, no data can enter or leave Port 5001 without passing through TLS encryption.
        self.ssl_server_socket = self.ssl_context.wrap_socket(raw_tcp, server_side=True)
        logger.info(f"SSL/TCP auth channel ready on port {ssl_port}")

        # ─── 3. State Management Data Structures ──────────────────────────────
        self.subscribers       = set()  # Set of active client (IP, UDP Port) tuples
        self.client_heartbeats = {}     # Dictionary tracking exact time of last heard heartbeat
        self.running           = True   # Master kill switch for all threads
        self.loss_rate         = loss_rate

        self.seq_num              = 0   # Monotonically increasing notification counter
        self.unacked              = {}  # To-Do list dict of packets waiting for an ACK
        self.retransmission_count = 0 

        # threading.Lock() is a critical safety mechanism.
        # Since we run 3 threads in parallel, if Thread A deletes a client exactly when 
        # Thread B tries to send a message to that client, Python will crash.
        # The Lock forces threads to take turns modifying memory safely.
        self._lock = threading.Lock()

    # ────────────────────────────────────────────────────────────────────────
    # THREAD 1: TCP/SSL CONNECTION ACCEPTOR
    # ────────────────────────────────────────────────────────────────────────

    def accept_ssl_clients(self):
        """
        Background infinite loop — sole purpose is to stand at the door 
        and accept secure TLS connection handshakes.
        """
        logger.info("SSL auth channel accepting connections...")
        while self.running:
            try:
                # Blocks here until a client securely knocks and passes the handshake
                client_ssl, tcp_addr = self.ssl_server_socket.accept()

                # Span a brand new mini-thread just to handle this specific client's subscription.
                # Why? So the main server loop doesn't freeze up if this client's internet is slow.
                t = threading.Thread(
                    target=self._handle_ssl_auth,
                    args=(client_ssl, tcp_addr),
                    daemon=True
                )
                t.start()
            except Exception:
                break

    def _handle_ssl_auth(self, client_ssl, tcp_addr):
        """
        Processes a newly connected client, extracts their UDP port, and hangs up.
        """
        try:
            # Use our custom TCP Stream helper to extract exactly one full packet safely
            seq, msg_type, payload, valid = recv_packet(client_ssl)

            if valid and msg_type == TYPE_SUBSCRIBE:
                # The payload text literally contains the client's randomly assigned UDP port
                udp_port = int(payload.strip())

                # Marry the client's public IP address with their secret UDP port
                client_udp_addr = (tcp_addr[0], udp_port)

                # Safely write this new client to memory
                with self._lock:
                    self.subscribers.add(client_udp_addr)
                    self.client_heartbeats[client_udp_addr] = time.time()  # Start their heartbeat timer

                logger.info(f"New subscriber via SSL: UDP addr = {client_udp_addr} [TLS: {client_ssl.version()}]")

        except Exception as e:
            logger.error(f"Error in SSL auth: {e}")
        finally:
            # Mission accomplished. Violently sever the TCP connection. 
            # We will talk to them via UDP from now on.
            client_ssl.close()

    # ────────────────────────────────────────────────────────────────────────
    # THREAD 2: UDP DATAGRAM RECEIVER
    # ────────────────────────────────────────────────────────────────────────

    def listen_udp(self):
        """
        Background infinite loop — waits for random UDP packets to fall from the sky.
        Will only process incoming ACKs, HEARTBEATs, and UNSUBSCRIBEs.
        """
        while self.running:
            try:
                data, addr = self.udp_socket.recvfrom(4096)
                seq, msg_type, payload, valid = decode_packet(data)

                if not valid:
                    continue  # The physical internet corrupted this packet. Toss it in the bin.

                if msg_type == TYPE_ACK:
                    # Excellent, the client received our notification message.
                    # Lock memory and strike that message off the 'Unacked To-Do list'.
                    with self._lock:
                        if (seq, addr) in self.unacked:
                            del self.unacked[(seq, addr)]
                            logger.info(f"ACK received for seq {seq} from {addr}")

                elif msg_type == TYPE_HEARTBEAT:
                    # Client is alive! Update their last seen timestamp array to right now.
                    with self._lock:
                        if addr in self.subscribers:
                            self.client_heartbeats[addr] = time.time()

                elif msg_type == TYPE_UNSUBSCRIBE:
                    # Client gracefully wants to leave the group. Purge them from memory.
                    self._remove_client(addr)
                    logger.info(f"Client {addr} unsubscribed gracefully")

            except Exception:
                continue

    def _remove_client(self, addr):
        """Helper function to violently purge a client from all memory dictionaries."""
        with self._lock:
            self.subscribers.discard(addr)
            self.client_heartbeats.pop(addr, None)
            
            # Wipe any pending deliveries destined for this dead client
            keys_to_remove = [k for k in self.unacked if k[1] == addr]
            for k in keys_to_remove:
                del self.unacked[k]

    # ────────────────────────────────────────────────────────────────────────
    # BROADCAST PIPELINE (The Megaphone)
    # ────────────────────────────────────────────────────────────────────────

    def broadcast(self, message):
        """
        Takes terminal input and shoots the UDP datagram to all subscribers.
        """
        message = message.strip()
        if not message: return

        with self._lock:
            self.seq_num += 1
            current_seq = self.seq_num

        # Embed our local timestamp into the payload ('1712345678.12|Hello')
        # We do this so the client can subtract server time from client time to calculate network latency!
        payload = f"{time.time()}|{message}"
        packet  = encode_packet(current_seq, TYPE_NOTIFY, payload)

        with self._lock:
            subscriber_snapshot = set(self.subscribers)

        # Loop through every single VIP client
        for addr in subscriber_snapshot:
            # Academic testing hack: randomly drop packets to prove our retransmission works
            if random.random() < self.loss_rate: continue

            try:
                self.udp_socket.sendto(packet, addr)
                
                # Instantly write an overdue note: "I sent message X to client Y at Z time. They have 0 retries."
                with self._lock:
                    self.unacked[(current_seq, addr)] = {
                        "addr": addr, "packet": packet,
                        "timestamp": time.time(), "retries": 0
                    }
            except Exception:
                pass

        logger.info(f"Broadcast seq {current_seq} pushed to {len(subscriber_snapshot)} clients")

    # ────────────────────────────────────────────────────────────────────────
    # THREAD 3: RELIABILITY GARBAGE COLLECTOR
    # ────────────────────────────────────────────────────────────────────────

    def retransmission_thread(self):
        """
        Background infinite loop — runs every 1 second.
        Hunts down missing packets and evicts dead connections.
        """
        while self.running:
            current_time = time.time()

            # --- 1) Retransmission / Retry Protocol --- # 
            with self._lock:
                unacked_snapshot = dict(self.unacked)

            for key, entry in unacked_snapshot.items():
                seq, addr = key

                # Has it been more than 2 seconds since we fired the packet without an ACK returning?
                if current_time - entry["timestamp"] > 2:
                    if entry["retries"] >= 3:
                        # We gave them 3 tries and still nothing. Give up and silently discard the packet.
                        with self._lock:
                            self.unacked.pop(key, None)
                        continue

                    # PANIC! Fire the UDP packet a second time.
                    try:
                        self.udp_socket.sendto(entry["packet"], entry["addr"])
                        with self._lock:
                            if key in self.unacked:
                                self.unacked[key]["timestamp"] = current_time   # Reset the 2 second clock
                                self.unacked[key]["retries"]  += 1              # Increment strike counter
                        logger.info(f"Retransmitting seq {seq} to {addr}")
                    except Exception:
                        pass

            # --- 2) Heartbeat Sweeper Protocol --- # 
            with self._lock:
                heartbeat_snapshot = dict(self.client_heartbeats)

            # Has it been over 5 seconds since client Z sent a ping? 
            # Their Wi-Fi disconnected or app crashed. Evict them immediately.
            for addr, last_beat in heartbeat_snapshot.items():
                if current_time - last_beat > 5.0:
                    logger.warning(f"Timeout Eviction: {addr} offline (5 sec without heartbeat ping).")
                    self._remove_client(addr)

            time.sleep(1)

if __name__ == "__main__":
    server = NotificationServer()
    
    # Ignite all three parallel engine loops
    threading.Thread(target=server.accept_ssl_clients, daemon=True).start()
    threading.Thread(target=server.listen_udp, daemon=True).start()
    threading.Thread(target=server.retransmission_thread, daemon=True).start()

    print("\n Hybrid SSL/UDP Server activated!")
    print("\n Type any message to broadcast to all subscribers. (Ctrl+C to cancel)\n")

    try:
        # Keep the main loop locked on terminal input
        while True:
            msg = input()
            server.broadcast(msg)
    except KeyboardInterrupt:
        server.running = False