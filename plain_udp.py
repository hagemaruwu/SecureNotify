"""
plain_udp.py
Author: Aditya Raj
Description:
    A Best-Effort UDP notification system that INTENTIONALLY has NO reliability features.
    This is the BASELINE / CONTROL GROUP used to compare against our Reliable SSL system.

    Key differences from server.py / client.py:
      - NO SSL/TLS encryption        (plain UDP datagrams, no handshake)
      - NO ACKs sent by the client   (server never knows if delivery succeeded)
      - NO retransmission logic      (server sends once and immediately forgets)
      - NO heartbeat / keep-alive    (dead clients linger until manually cleaned)
      - NO sequence number tracking  (duplicates are not detected or filtered)

    Why keep this?
      This proves WHY reliability and security matter. In tests at 30% packet loss:
        - Plain UDP delivers only ~50–70% of messages.
        - Our Reliable SSL system consistently delivers 90–100%.
      The side-by-side comparison is the scientific justification for our design.

    Edge Cases in Plain UDP (deliberately unhandled — this is the point):
      - Abrupt client disconnection  → server never finds out; keeps sending to dead addr
      - Packet corruption            → basic CRC check discards it; nothing is retransmitted
      - Invalid input                → validate before calling broadcast() (see below)
      - Socket send errors           → caught and logged to prevent crashes
"""

import socket     # Python's built-in networking library
import threading  # Kept for consistency with the reliable version
import time       # For timestamp embedding (latency measurement)
import logging    # For structured log output
import random     # For simulating packet loss

# Reuse our custom protocol encoder/decoder from protocol.py.
# We use the SAME binary packet format so results are directly comparable.
# The only difference: no TYPE_ACK, no TYPE_HEARTBEAT, no TYPE_UNSUBSCRIBE handling.
from protocol import TYPE_SUBSCRIBE, TYPE_NOTIFY, encode_packet, decode_packet

logger = logging.getLogger("Plain_UDP")

# Maximum allowed broadcast message length (mirrors the reliable server's limit)
MAX_MESSAGE_LENGTH = 1000


class PlainNotificationServer:
    """
    A minimal UDP server with NO reliability or security layer.
    Registers subscribers and broadcasts messages — but if a packet is lost,
    it is never retransmitted. Used as the 'control group' baseline in testing.

    ── Deliberate Omissions (for comparison purposes) ───────────────────────────
    - No SSLContext                  → datagrams are transmitted in plaintext
    - No unacked tracker             → no follow-up if a client misses a message
    - No heartbeat eviction          → offline clients accumulate in the set
    - No per-client threads          → one receive loop handles everyone
    """

    def __init__(self, host="0.0.0.0", port=5000, loss_rate=0.0):
        """
        Sets up and binds the plain UDP server socket.

        Args:
            host:      IP address to bind.
            port:      Port number (should differ from the reliable server's port during testing).
            loss_rate: Fraction [0.0–1.0] of datagrams to randomly drop (for testing).
        """
        self.server_addr = (host, port)

        # AF_INET = IPv4, SOCK_DGRAM = UDP (no connection, no handshake, no SSL)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Allow port reuse to prevent 'Address already in use' during quick restarts
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(self.server_addr)   # Attach socket to the chosen port

        self.subscribers = set()    # Set of (IP, port) tuples for registered clients
        self.running     = True     # Control flag — set False to stop the listen loop
        self.loss_rate   = loss_rate
        self.seq_num     = 0        # Monotonically increasing message counter

    def send_with_loss(self, packet, addr):
        """
        Sends a datagram to 'addr' with optional simulated packet loss.

        In a real network: packets are lost due to congestion, noise, or router drops.
        Here we simulate that artificially to test how the two systems compare.

        ── Edge Case: Send Failure ───────────────────────────────────────────────
        Unlike the reliable server, we do NOT remove the client from subscribers
        on failure — this is intentional: the plain server doesn't track connectivity.
        We just log the error and move on (fire-and-forget).
        """
        if random.random() < self.loss_rate:
            return  # Silently discard — simulates a packet lost in the network

        try:
            self.server_socket.sendto(packet, addr)
        except OSError as e:
            # ─── Edge Case: Socket Send Error ───────────────────────────────
            # Could occur if the client's port is no longer open (OS already recycled it).
            # We log and continue — the plain server never removes dead clients automatically.
            logger.warning(f"Send error to {addr}: {e} (client may be offline)")

    def listen(self):
        """
        Receive loop — runs on a background thread.

        The Plain server ONLY handles TYPE_SUBSCRIBE messages.
        It ignores everything else because:
          - There are no ACKs to process (we never request them)
          - There are no HEARTBEATs to process (we have no eviction logic)
          - There are no UNSUBSCRIBEs to process (clients just stop receiving)

        ── Notice: No Per-Client Thread ─────────────────────────────────────────
        Unlike the reliable server which spawns a thread per client via accept(),
        this single loop handles all incoming datagrams sequentially.
        OK for testing purposes; not suitable for high-throughput production use.
        """
        while self.running:
            try:
                data, addr = self.server_socket.recvfrom(4096)    # Block for next datagram
                seq, msg_type, payload, valid = decode_packet(data)

                if not valid:   # Corrupted packet → silently discard
                    continue

                if msg_type == TYPE_SUBSCRIBE:
                    self.subscribers.add(addr)  # Register this client's address

                # ─── Notice: No ACK handling here ─────────────────────────────
                # The Plain server never requests ACKs, so there's nothing to process.
                # Compare this to the reliable server's handle_client(), which processes
                # TYPE_ACK, TYPE_HEARTBEAT, and TYPE_UNSUBSCRIBE in addition to SUBSCRIBE.

            except Exception:
                pass    # Keep the loop alive; ignore transient errors

    def broadcast(self, message):
        """
        Sends a notification datagram to every subscriber ONCE and immediately forgets it.

        ── Input Validation (Edge Case) ─────────────────────────────────────────
        We validate the message here (mirrors the reliable server's validation)
        to prevent crashes from empty or excessively long inputs.

        ══ KEY DIFFERENCE FROM RELIABLE SERVER ══════════════════════════════════
        In reliable server's broadcast():
            self.unacked[(seq, addr)] = { "packet": ..., "retries": 0, ... }
            # → Retransmission thread will follow up in 2 seconds if no ACK arrives

        Here, there is NONE of that. We send once and move on.
        If a client's datagram is dropped → that client NEVER receives the message.
        This is the core weakness of best-effort UDP that our project solves.
        """
        # ─── Input Validation ─────────────────────────────────────────────────
        if not isinstance(message, str) or not message.strip():
            logger.warning("Plain broadcast rejected: invalid or empty message")
            return

        message = message.strip()

        if len(message) > MAX_MESSAGE_LENGTH:
            logger.warning(f"Plain broadcast rejected: message too long ({len(message)} chars)")
            return

        self.seq_num += 1   # Increment message counter

        # Embed timestamp for latency measurement (same format as the reliable server)
        # Format: "1712345678.123|<actual message>"
        payload = f"{time.time()}|{message}"
        packet  = encode_packet(self.seq_num, TYPE_NOTIFY, payload)

        # Send to every subscriber ONCE — no follow-up, no retry, no confirmation
        for addr in list(self.subscribers):
            self.send_with_loss(packet, addr)   # May be silently dropped!


class PlainNotificationClient:
    """
    A minimal UDP client with NO reliability or security features.
    Receives notifications but NEVER sends ACKs back to the server.
    Used as the 'control group' client in performance testing.

    ── Deliberate Omissions ─────────────────────────────────────────────────────
    - No SSL/TLS                 → datagrams are unencrypted
    - No ACK sending             → server never knows if delivery succeeded
    - No heartbeat               → server can't detect if this client went offline
    - No seq-based deduplication for retransmissions (none are sent anyway)
    """

    def __init__(self, server_host="127.0.0.1", server_port=5000, loss_rate=0.0):
        """
        Creates a UDP socket and connects it to the server address.

        Args:
            server_host: Server's IP address.
            server_port: Server's port number.
            loss_rate:   Fraction [0.0–1.0] of packets to randomly drop (testing).
        """
        self.server_addr = (server_host, server_port)

        # Plain UDP socket — no SSL wrapping, no connection state
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # connect() on UDP just sets the default destination address for send()
        # It does NOT perform any handshake — there is nothing to handshake for UDP.
        self.client_socket.connect(self.server_addr)

        self.received_seqs = set()   # Track received seq numbers (for deduplication)
        self.running       = True    # Control flag to stop the listener thread
        self.loss_rate     = loss_rate
        self.latencies     = []      # Measured latency values (seconds) for metrics

    def subscribe(self):
        """Sends a SUBSCRIBE datagram to register with the plain server."""
        packet = encode_packet(0, TYPE_SUBSCRIBE, "")
        self.send_with_loss(packet)

    def send_with_loss(self, packet):
        """
        Sends a datagram with optional simulated drop.

        ── Edge Case: Socket Error ───────────────────────────────────────────────
        Silently catches OSError to prevent crashes if the server isn't reachable.
        """
        if random.random() < self.loss_rate:
            return

        try:
            self.client_socket.send(packet)
        except OSError as e:
            logger.warning(f"Plain client send error: {e}")

    def listen(self):
        """
        Receive loop — runs on a background thread.
        Receives notifications and records latency for metrics.

        ══ KEY DIFFERENCE FROM RELIABLE CLIENT ═════════════════════════════════
        In reliable client's handle_notification():
            ack_packet = encode_packet(seq_num, TYPE_ACK, "")
            self.send_with_loss(ack_packet)   ← This line EXISTS in the reliable version
            # → Tells the server: "I got it, stop your retransmission timer"

        Here, there is NO such ACK send.
        The plain client silently receives and processes the message.
        The server has no way to know if this client received the notification or not.
        This is the fundamental difference that causes plain UDP's delivery rate to
        drop to 50–70% under 30% packet loss, while reliableUDP maintains 90–100%.
        """
        while self.running:
            try:
                data = self.client_socket.recv(4096)     # Wait for incoming datagram
                seq, msg_type, payload, valid = decode_packet(data)

                # Skip corrupted packets or non-notification messages
                if not valid or msg_type != TYPE_NOTIFY:
                    continue

                # ─── NO ACK IS SENT ────────────────────────────────────────────
                # This is the critical omission. The reliable client would send:
                #   self.send_with_loss(encode_packet(seq, TYPE_ACK, ""))
                # But here we just move on silently.

                if seq not in self.received_seqs:
                    self.received_seqs.add(seq)     # Note: won't receive duplicates anyway
                                                    # since the server never retransmits

                    # Extract embedded timestamp to calculate end-to-end latency
                    # Same format: "1712345678.123|<actual message>"
                    if isinstance(payload, str) and "|" in payload:
                        parts = payload.split("|", 1)
                        if len(parts) == 2:
                            try:
                                sent_ts = float(parts[0])
                                latency = time.time() - sent_ts
                                self.latencies.append(latency)  # Store for test metrics
                            except ValueError:
                                pass

            except OSError as e:
                # ─── Edge Case: Socket Error ───────────────────────────────────
                if self.running:
                    logger.warning(f"Plain client receive error: {e}")
            except Exception:
                pass    # Silently ignore to keep the loop stable
