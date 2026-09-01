"""
client.py
Author: Aditya Raj
Description:
    This file is the Subscriber Client of the Reliable Group Notification System.
    Why does this file exist?
    A client application needs to be incredibly lightweight so it takes up virtually
    no CPU or memory running in the background. It is designed to be completely "stupid"
    by design. It just connects to the server, listens quietly on a random port,
    instantly screams "ACK" when data drops in, and displays the UI text. It relies 
    entirely on server.py to do the heavy mathematical lifting.

    ── Hybrid Architecture Checkout ─────────────────────────────────────────────
    The client interacts with TWO distinct networks:

    1. SSL/TCP Authentication Channel (Server port 5001)
       - Used solely to establish a highly secure TLS tunnel for the initial handshake.
       - The client pushes its random UDP port through the tunnel.
       - Hangs up the connection immediately to save server bandwidth (one-shot auth).

    2. UDP Data Channel (Local random port -> Server port 5000)
       - Sits idle waiting for massive NOTIFY broadcasts to fall from the sky.
       - Blasts ACKs back upward through UDP.
       - Blasts Heartbeat pings upward to prove it is still alive.
"""

import socket     # Built-in network socket interface
import ssl        # Cryptographic library to generate secure session keys
import threading  # Allows parallel thread loops so the listener doesn't freeze the console
import time       # Embedded calculation logic for subtracting transmission time (latency)
import logging    # Professional formatted terminal output
import random     # Simulates aggressive network failure in academic test scenarios
import sys        # Allows us to capture arguments written in the terminal (like IP variables)

# Import our universal binary language dictionary and network tools
from protocol import (
    TYPE_SUBSCRIBE, TYPE_NOTIFY, TYPE_ACK,
    TYPE_UNSUBSCRIBE, TYPE_HEARTBEAT,
    encode_packet, decode_packet
)

# ─── Default Server Endpoints ────────────────────────────────────────────────
SERVER_HOST     = "127.0.0.1"    # Loopback IP (used if no CLI argument is provided)
SERVER_UDP_PORT = 5000           # The server's UDP target (Must perfectly match server.py)
SERVER_SSL_PORT = 5001           # The server's VIP TCP target (Must perfectly match server.py)

# Standard logging formatter
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger("Hybrid_Client")


class NotificationClient:
    def __init__(self, server_host=SERVER_HOST, server_udp_port=SERVER_UDP_PORT,
                 server_ssl_port=SERVER_SSL_PORT, loss_rate=0.0, verbose=True):
        """
        Architects both the UDP postbox and the SSL keys upon software startup.
        """
        self.server_host     = server_host
        self.server_udp_addr = (server_host, server_udp_port)  # Target for ACK and HEARTBEAT
        self.server_ssl_addr = (server_host, server_ssl_port)  # Target for one-off SUBSCRIBE

        # ─── 1. Build Local UDP Socket ───────────────────────────────────────
        # AF_INET = IPv4 Internet. SOCK_DGRAM = Connectionless UDP Datagram.
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Brilliant Hack: By binding to Port '0', we force the Operating System
        # to randomly assign us any perfectly free port. We do this so multiple
        # clients running on the same laptop don't accidentally try to use the same port!
        self.udp_socket.bind(("", 0))

        # Ask the OS: "What port number did you just give me?"
        # We save this number so we can securely message it to the server!
        self.udp_port = self.udp_socket.getsockname()[1]
        logger.info(f"UDP data channel bound to local port {self.udp_port}")

        # ─── 2. Build SSL Context ────────────────────────────────────────────
        # Prepare to act as a client negotiating a TLS handshake
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # Because we are using a self-made, unpaid server certificate (not via Google Auth), 
        # the OS will inherently block the connection. We explicitly bypass hostname checks
        # to force Python to trust the custom certificate we made.
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode    = ssl.CERT_NONE  

        # ─── Client Memory ───────────────────────────────────────────────────
        self.received_seqs = set()      # Safety log to prevent duplicate messages
        self.running       = True       # Master kill switch for all threads
        self.loss_rate     = loss_rate  # Artificially drops packets
        self.verbose       = verbose    # Flag to hide text output during massive tests
        self.latencies     = []         # Array to store all mathematical latency times

    # ────────────────────────────────────────────────────────────────────────
    # AUTHENTICATION HOOKS
    # ────────────────────────────────────────────────────────────────────────

    def subscribe(self):
        """
        Initiates the secure handshake sequence.
        Transmits our UDP port number deeply encrypted to bypass Wi-Fi snoopers.
        """
        try:
            # Step 1: Establish physical TCP bridge to the server.
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.connect(self.server_ssl_addr)

        except ConnectionRefusedError:
            logger.critical(f"Cannot connect to SSL auth server at {self.server_ssl_addr}. Is server.py running?")
            return

        try:
            # Step 2: Push the raw bridge through our SSL cryptographic machine
            ssl_sock = self.ssl_context.wrap_socket(raw_sock, server_hostname=self.server_host)
            logger.info(f"SSL auth connected [{ssl_sock.version()}]. Sending SUBSCRIBE (UDP port: {self.udp_port})...")

            # Step 3: Embed our randomly generated UDP port into the payload string
            packet = encode_packet(0, TYPE_SUBSCRIBE, str(self.udp_port))
            ssl_sock.sendall(packet)

            # Step 4: Drop the bridge. The server will now communicate solely via UDP.
            ssl_sock.close()
            logger.info("SSL auth complete. Now receiving on UDP channel.")

        except ssl.SSLError as e:
            logger.critical(f"SSL handshake failed: {e}")
            raw_sock.close()
        except Exception as e:
            logger.error(f"Subscribe failed: {e}")

    def unsubscribe(self):
        """
        Respectfully request eviction via the fast UDP channel.
        """
        logger.info("Sending UNSUBSCRIBE via UDP...")
        packet = encode_packet(0, TYPE_UNSUBSCRIBE, str(self.udp_port))
        self.send_udp(packet)

    # ────────────────────────────────────────────────────────────────────────
    # THREAD 1: BACKGROUND PINGER
    # ────────────────────────────────────────────────────────────────────────

    def heartbeat_loop(self):
        """
        The invisible ninja thread.
        Awakens every 2 seconds, generates an empty Type 5 payload, fires it at 
        the server, and goes back to sleep. Stops the server from auto-evicting us.
        """
        while self.running:
            try:
                packet = encode_packet(0, TYPE_HEARTBEAT, "")
                self.send_udp(packet)
            except Exception:
                pass  # Do not crash the thread if the Wi-Fi card hangs
            time.sleep(2.0)  

    # ────────────────────────────────────────────────────────────────────────
    # OUTBOUND UDP FIRING MECHANISM
    # ────────────────────────────────────────────────────────────────────────

    def send_udp(self, packet):
        """
        Takes raw binary packets and shoots them out of our Datagram socket
        directly up into the Server UDP Address.
        """
        # Academic testing logic: If we roll the dice below the drop percent, delete packet!
        if random.random() < self.loss_rate:
            logger.warning("Simulated DROP (client -> server, UDP)")
            return

        try:
            # sendto() does not require a prior connection state
            self.udp_socket.sendto(packet, self.server_udp_addr)
        except OSError as e:
            logger.error(f"UDP send error: {e}")

    # ────────────────────────────────────────────────────────────────────────
    # THREAD 2: UDP LISTENER
    # ────────────────────────────────────────────────────────────────────────

    def listen(self):
        """
        Background infinite loop — waits silently for massive server blasts.
        """
        while self.running:
            try:
                # Execution halts here until data drops down from the cloud
                data, addr = self.udp_socket.recvfrom(4096)
                
                # Slices the sequence, type, payload, and physically verifies mathematical CRC32 checksums
                seq_num, msg_type, payload, is_valid = decode_packet(data)

                # Packet was garbled slightly by physical internet static interference. Reject.
                if not is_valid:
                    logger.warning("Corrupted UDP packet received — discarding")
                    continue

                if msg_type == TYPE_NOTIFY:
                    self.handle_notification(seq_num, payload)

            except OSError as e:
                if self.running:
                    logger.error(f"UDP receive error: {e}")
                continue
            except Exception as e:
                continue

    # ────────────────────────────────────────────────────────────────────────
    # NOTIFICATION PARSER & LOGIC ENGINE
    # ────────────────────────────────────────────────────────────────────────

    def handle_notification(self, seq_num, message):
        """
        The absolute fastest execution block in the codebase.
        1. Explodes an ACK backward.
        2. Blocks duplicated retransmissions.
        3. Isolates network latency math.
        4. Renders output text physically to the screen display.
        """
        
        # Step 1: EXTREMELY CRITICAL ORDER OF OPERATIONS!
        # Before we even read the message text, we MUST fire a Type 3 ACK backward. 
        # We must respond instantly to stop the far-away Server from triggering its panic queue timer!
        logger.info(f"Received notification seq {seq_num}. Sending ACK via UDP...")
        ack_packet = encode_packet(seq_num, TYPE_ACK, "")
        self.send_udp(ack_packet)

        # Step 2: The Duplicate Blocker
        # If we received Message #5 but our ACK was jammed in network traffic, the Server
        # will violently shoot Message #5 at us again. If we already saw the sequence ID, 
        # we completely ignore it.
        if seq_num in self.received_seqs:
            logger.info(f"Duplicate seq {seq_num} — already processed, ignoring")
            return

        self.received_seqs.add(seq_num)

        actual_message = message

        # Step 3: Latency Calculator
        # The sever prefixes all blasts with clock math (`1712345678.12|Hello`)
        # We split the string structure by its delimiter ('|')
        # We take the server's origination timestamp, and subtract it against our own hardware clock!
        if isinstance(message, str) and "|" in message:
            parts = message.split("|", 1)
            if len(parts) == 2:
                try:
                    sent_ts        = float(parts[0])         
                    latency        = time.time() - sent_ts   # Measure elapsed air travel time
                    self.latencies.append(latency)
                    actual_message = parts[1]                # Snip cleanly to preserve UX Message Integrity
                except ValueError:
                    pass

        # Step 4: Render UX text block
        if self.verbose:
            print(f"\n>>> NOTIFICATION [{seq_num}]: {actual_message}\n")

    # ────────────────────────────────────────────────────────────────────────
    # MAIN PROGRAM EXECUTION
    # ────────────────────────────────────────────────────────────────────────

    def start(self):
        """
        Fires execution sequence: Subscribe -> Start Listaner -> Start Heartbeat
        """
        self.subscribe()  

        # Daemon threads mean they will automatically terminate if the primary script closes
        listener_thread = threading.Thread(target=self.listen, daemon=True)
        listener_thread.start()

        heartbeat_thread = threading.Thread(target=self.heartbeat_loop, daemon=True)
        heartbeat_thread.start()

        print(f"\nConnected! Receiving notifications on UDP port {self.udp_port}.")
        print("Type 'quit' and press Enter to disconnect cleanly.\n")

        try:
            while self.running:
                msg = input()
                if msg.lower() == 'quit':
                    self.unsubscribe()   
                    self.running = False 
        except KeyboardInterrupt:
            self.unsubscribe()
            self.running = False


if __name__ == "__main__":
    # Command Line Interface (CLI) IP target logic.
    # Enables dynamic friend testing like: "python client.py 192.168.1.5"
    # If no argument is passed, it intelligently defaults to localhost (127.0.0.1)
    host = sys.argv[1] if len(sys.argv) > 1 else SERVER_HOST
    client = NotificationClient(server_host=host)
    client.start()