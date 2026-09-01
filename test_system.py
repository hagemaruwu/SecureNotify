"""
test_system.py
Author: Aditya Raj
Description:
    Automated performance testing framework for the Reliable Group Notification System.

    This script:
      1. Runs BOTH the Reliable Hybrid (SSL/TCP auth + UDP data) system AND the
         Best-Effort Plain UDP system under identical, controlled conditions.
      2. Simulates four levels of network packet loss: 0%, 10%, 20%, 30%.
      3. Measures four performance metrics for each mode:
           - Delivery Rate       : % of notifications actually received by clients
           - Retransmission Count: extra sends needed to guarantee delivery
           - Average Latency     : mean end-to-end time from server send to client receipt
           - Throughput          : messages delivered per second (system capacity)
      4. Generates a 4-panel performance comparison graph saved as
         'performance_results.png'.

    ── Port Scheme ──────────────────────────────────────────────────────────────
    Each test run uses unique ports to avoid "address already in use" errors:
      Test i (Reliable): udp_port = 5000 + i*4,  ssl_port = 5001 + i*4
      Test i (Plain UDP): udp_port = 5002 + i*4  (no SSL port needed)
"""

import time       # For sleep timers and throughput measurement
import threading  # For running server/client threads in the background
import math       # Available for potential float calculations

# ─── Optional Matplotlib Import ──────────────────────────────────────────────
try:
    import matplotlib.pyplot as plt
    PLOTTING_ENABLED = True
except ImportError:
    print("[WARNING] matplotlib not installed. Install with: pip install matplotlib")
    PLOTTING_ENABLED = False

# ─── Import Both System Implementations ──────────────────────────────────────
# Reliable system: SSL/TCP for auth (SUBSCRIBE) + UDP for data (NOTIFY, ACK, etc.)
from server    import NotificationServer
from client    import NotificationClient
# Baseline system: plain UDP — no SSL, no ACKs, no retransmission
from plain_udp import PlainNotificationServer, PlainNotificationClient


def run_test(loss_rate, udp_port, ssl_port=None, mode="reliable",
             num_clients=3, num_notifications=5):
    """
    Executes ONE complete test scenario and returns four performance metrics.

    For reliable mode:
      - Server needs both a UDP data port and an SSL/TCP auth port.
      - Clients connect via SSL/TCP first (SUBSCRIBE), then use UDP for data.

    For plain mode:
      - Server uses only a UDP port (no SSL).
      - Clients use only UDP (no SSL, no ACKs, no retransmission).

    Args:
        loss_rate       (float): Fraction of packets to drop [0.0–0.3].
        udp_port        (int):   UDP data port for this test run.
        ssl_port        (int):   SSL/TCP auth port (reliable mode only).
        mode            (str):   "reliable" or "plain".
        num_clients     (int):   Number of subscriber clients to simulate.
        num_notifications(int):  Number of broadcast messages to send.

    Returns:
        (delivery_rate, retransmissions, avg_latency, throughput)
    """
    print(f"\n{'─'*60}")
    print(f"  Test: {mode.upper()} | Loss: {loss_rate*100:.0f}% | "
          f"UDP:{udp_port}" + (f" SSL:{ssl_port}" if ssl_port else ""))
    print(f"{'─'*60}")

    # ─── Step 1: Start the Server ──────────────────────────────────────────────
    if mode == "reliable":
        # Hybrid server: SSL/TCP auth on ssl_port, UDP data on udp_port
        server = NotificationServer(udp_port=udp_port, ssl_port=ssl_port,
                                    loss_rate=loss_rate)

        # Thread A: accepts SSL/TCP SUBSCRIBE connections from clients
        ssl_thread = threading.Thread(target=server.accept_ssl_clients, daemon=True)

        # Thread B: receives ACKs, HEARTBEATs, UNSUBSCRIBEs on UDP
        udp_thread = threading.Thread(target=server.listen_udp, daemon=True)

        # Thread C: checks for unACK'd packets (retransmit) and dead clients (evict)
        retrans_thread = threading.Thread(target=server.retransmission_thread, daemon=True)

        ssl_thread.start()
        udp_thread.start()
        retrans_thread.start()

        # Give SSL server time to fully bind before clients try to connect
        time.sleep(0.5)

    else:
        # Plain UDP baseline server — no SSL, no retransmission, single thread
        server = PlainNotificationServer(port=udp_port, loss_rate=loss_rate)
        server_thread = threading.Thread(target=server.listen, daemon=True)
        server_thread.start()
        time.sleep(0.2)

    # ─── Step 2: Create Clients and Subscribe ─────────────────────────────────
    clients = []
    for i in range(num_clients):
        try:
            if mode == "reliable":
                # Hybrid client: will subscribe via SSL/TCP then receive on UDP
                client = NotificationClient(
                    server_udp_port=udp_port,
                    server_ssl_port=ssl_port,
                    loss_rate=loss_rate,
                    verbose=False           # Suppress output during automated tests
                )
                # Thread: listens for NOTIFY on client's UDP socket
                t = threading.Thread(target=client.listen, daemon=True)
                t.start()
                # Thread: sends HEARTBEAT pings to server every 2 seconds
                hb = threading.Thread(target=client.heartbeat_loop, daemon=True)
                hb.start()

            else:
                # Plain UDP client — no SSL, no ACKs, simple UDP listener
                client = PlainNotificationClient(server_port=udp_port, loss_rate=loss_rate)
                t = threading.Thread(target=client.listen, daemon=True)
                t.start()

            client.subscribe()      # SUBSCRIBE (SSL/TCP for reliable, UDP for plain)
            clients.append(client)

        except Exception as e:
            print(f"[ERROR] Client {i+1} setup failed: {e}")

    # ─── Step 3: Wait for All Clients to Subscribe ────────────────────────────
    # For hybrid mode, the SSL handshake + SUBSCRIBE takes a moment.
    # We poll every second and retry subscribes if some were dropped.
    print("Waiting for all clients to subscribe...")
    start_wait = time.time()

    while len(server.subscribers) < num_clients and time.time() - start_wait < 6:
        for c in clients:
            try:
                if len(server.subscribers) < num_clients:
                    c.subscribe()   # Retry SUBSCRIBE if the first attempt was dropped
            except Exception:
                pass
        time.sleep(1)

    if len(server.subscribers) < num_clients:
        print(f"[WARNING] Only {len(server.subscribers)}/{num_clients} clients subscribed")
    else:
        print(f"All {num_clients} clients subscribed. Broadcasting...")

    # ─── Step 4: Broadcast and Measure Throughput ─────────────────────────────
    # Record the start time so we can compute throughput (msgs/sec) later.
    broadcast_start = time.time()

    for i in range(num_notifications):
        try:
            server.broadcast(f"Test message {i+1}")    # UDP broadcast to all subscribers
        except Exception as e:
            print(f"[ERROR] Broadcast {i+1} failed: {e}")
        time.sleep(0.5)     # Small gap to avoid flooding the network

    broadcast_elapsed = time.time() - broadcast_start

    # ─── Step 5: Wait for Delivery to Complete ────────────────────────────────
    if mode == "reliable":
        # Extra time for retransmissions: server waits 2s before retrying.
        # We give 6s total buffer to allow up to 3 retries to complete.
        time.sleep(6)
    else:
        # Plain UDP is fire-and-forget — no retransmissions to wait for.
        time.sleep(1)

    # ─── Step 6: Compute Metrics ──────────────────────────────────────────────

    # Delivery Rate: what % of notifications actually reached each client?
    total_expected = num_clients * num_notifications
    total_received = sum(len(c.received_seqs) for c in clients)
    delivery_rate  = (total_received / total_expected * 100) if total_expected > 0 else 0.0

    # Retransmissions: how many extra UDP sends were needed? (0 for plain)
    retransmissions = getattr(server, "retransmission_count", 0)

    # Average Latency: mean time from server send to client receipt (in seconds)
    all_latencies = []
    for c in clients:
        if hasattr(c, 'latencies'):
            all_latencies.extend(c.latencies)
    avg_latency = (sum(all_latencies) / len(all_latencies)) if all_latencies else 0.0

    # Throughput: total messages received across all clients per second of broadcast time
    # This measures the effective delivery capacity of the system under this loss rate.
    throughput = (total_received / broadcast_elapsed) if broadcast_elapsed > 0 else 0.0

    print(f"\nResults [{mode.upper()} @ {loss_rate*100:.0f}% loss]:")
    print(f"  Delivery Rate  : {delivery_rate:.2f}%")
    print(f"  Retransmissions: {retransmissions}")
    print(f"  Avg Latency    : {avg_latency * 1000:.2f} ms")
    print(f"  Throughput     : {throughput:.2f} msgs/sec")

    # ─── Step 7: Cleanup ──────────────────────────────────────────────────────
    server.running = False

    for c in clients:
        try:
            if hasattr(c, 'unsubscribe'):
                c.unsubscribe()             # Gracefully notify server before closing
            c.running = False
            if hasattr(c, 'udp_socket'):
                c.udp_socket.close()        # Hybrid client: close the UDP socket
            elif hasattr(c, 'client_socket'):
                c.client_socket.close()     # Plain UDP client: close its socket
        except Exception:
            pass

    try:
        if hasattr(server, 'udp_socket'):
            server.udp_socket.close()       # Release the UDP data port
        if hasattr(server, 'ssl_server_socket'):
            server.ssl_server_socket.close()    # Release the SSL auth port
        if hasattr(server, 'server_socket'):
            server.server_socket.close()    # Plain UDP server socket
    except Exception:
        pass

    time.sleep(0.5)     # Brief pause to let OS fully release ports before next test

    return delivery_rate, retransmissions, avg_latency, throughput


if __name__ == "__main__":
    # ─── Test Configuration ────────────────────────────────────────────────────
    loss_rates = [0.0, 0.1, 0.2, 0.3]  # 0%, 10%, 20%, 30% packet loss

    # Result lists for graph generation
    rel_delivery   = []
    rel_retrans    = []
    rel_latency    = []
    rel_throughput = []

    plain_delivery   = []
    plain_latency    = []
    plain_throughput = []

    # ─── Run All Tests ──────────────────────────────────────────────────────────
    for i, lr in enumerate(loss_rates):
        # Port allocation: each test gets 4 unique ports (i*4 offset)
        # Reliable: UDP data on 5000+i*4, SSL auth on 5001+i*4
        # Plain UDP: data on 5002+i*4
        port_udp    = 5000 + i * 4
        port_ssl    = 5001 + i * 4
        port_plain  = 5002 + i * 4

        # Run reliable hybrid (SSL/TCP auth + UDP data)
        dr, rc, lat, tp = run_test(lr, port_udp, ssl_port=port_ssl, mode="reliable")
        rel_delivery.append(dr)
        rel_retrans.append(rc)
        rel_latency.append(lat * 1000)      # seconds → milliseconds
        rel_throughput.append(tp)

        # Run plain UDP baseline (no SSL, no ACKs)
        dr_p, _, lat_p, tp_p = run_test(lr, port_plain, mode="plain")
        plain_delivery.append(dr_p)
        plain_latency.append(lat_p * 1000)
        plain_throughput.append(tp_p)

    # ─── Generate Performance Comparison Graphs ────────────────────────────────
    if PLOTTING_ENABLED:
        try:
            fig, axes = plt.subplots(1, 4, figsize=(22, 5))
            loss_pct = [lr * 100 for lr in loss_rates]

            # Graph 1: Delivery Rate
            # Shows what % of messages reached clients — reliable stays ~100%, plain drops
            axes[0].plot(loss_pct, rel_delivery,   marker='o', label='Reliable SSL+UDP', color='royalblue')
            axes[0].plot(loss_pct, plain_delivery, marker='x', label='Plain UDP',        color='crimson', linestyle='--')
            axes[0].set_xlabel('Packet Loss Rate (%)')
            axes[0].set_ylabel('Delivery Rate (%)')
            axes[0].set_title('Delivery Rate Comparison')
            axes[0].set_ylim(0, 108)
            axes[0].legend()
            axes[0].grid(True, alpha=0.3)

            # Graph 2: Average Latency
            # Reliable latency rises at high loss (retransmissions add delay).
            # Plain stays lower — but that's because undelivered messages aren't counted!
            axes[1].plot(loss_pct, rel_latency,   marker='o', label='Reliable SSL+UDP', color='royalblue')
            axes[1].plot(loss_pct, plain_latency, marker='x', label='Plain UDP',        color='crimson', linestyle='--')
            axes[1].set_xlabel('Packet Loss Rate (%)')
            axes[1].set_ylabel('Average Latency (ms)')
            axes[1].set_title('Average Latency Comparison')
            axes[1].legend()
            axes[1].grid(True, alpha=0.3)

            # Graph 3: Retransmission Overhead (Reliable System Only)
            # Shows HOW MUCH extra work the server did at each loss level to guarantee delivery.
            axes[2].bar(loss_pct, rel_retrans, width=6, color='darkorange', alpha=0.75,
                        label='Reliable SSL+UDP')
            axes[2].set_xlabel('Packet Loss Rate (%)')
            axes[2].set_ylabel('Total Retransmissions')
            axes[2].set_title('Retransmission Overhead\n(Reliable system only)')
            axes[2].legend()
            axes[2].grid(True, alpha=0.3, axis='y')

            # Graph 4: Throughput
            # Messages delivered per second across all clients.
            axes[3].plot(loss_pct, rel_throughput,   marker='o', label='Reliable SSL+UDP', color='royalblue')
            axes[3].plot(loss_pct, plain_throughput, marker='x', label='Plain UDP',        color='crimson', linestyle='--')
            axes[3].set_xlabel('Packet Loss Rate (%)')
            axes[3].set_ylabel('Throughput (msgs/sec)')
            axes[3].set_title('Throughput Comparison')
            axes[3].legend()
            axes[3].grid(True, alpha=0.3)

            plt.suptitle('Reliable (SSL/TCP auth + UDP data) vs Best-Effort UDP — Performance Analysis',
                         fontsize=12, fontweight='bold')
            plt.tight_layout()
            plt.savefig('performance_results.png', dpi=150)
            print("\nTest complete. Graph saved to 'performance_results.png'.")

        except Exception as e:
            print(f"[WARNING] Graph generation failed: {e}")
    else:
        print("\nTest complete. (Graph skipped — install matplotlib to generate graphs)")