# SecureNotify — Reliable Group Notification System

A secure, high-performance group notification engine engineered with a hybrid **TLS 1.3 authentication** and **UDP broadcast** architecture with application-layer reliability.

Developed by **[Aditya Raj](https://github.com/hagemaruwu)**.

---

## 📌 Overview

SecureNotify provides enterprise-grade message broadcast reliability over lossy network channels using low-level POSIX socket programming. Key capabilities include:

- **Hybrid Architecture:** TLS 1.3 (TCP) for authenticated subscription handshakes and UDP for ultra-fast, non-blocking broadcast delivery.
- **Custom Binary Protocol:** Frame structure containing sequence numbers, type identifiers, payload length, and CRC32 checksums for corruption detection.
- **Application-Layer Reliability:** Priority-tiered ACK tracking, retransmissions, per-client state isolation, and duplicate suppression.
- **Keep-Alive & Heartbeat:** Active client health monitoring with automatic eviction of dead or unresponsive subscribers.
- **Benchmarking Harness:** Automated test runner evaluating delivery rate, latency, retransmissions, and throughput under 0%–30% simulated packet loss.

---

## 🏗️ System Architecture — Hybrid (SSL/TCP Auth + UDP Data)

```
                      NOTIFICATION SERVER (server.py)
                      ┌──────────────────────────────────────────────┐
                      │                                              │
    Port 5001         │  ┌────────────────────────────────────────┐  │
  ┌─SSL/TCP Auth──────┤  │  accept_ssl_clients() thread           │  │
  │  (SUBSCRIBE only) │  │  → TLS 1.3 handshake (server.crt/.key) │  │
  │                   │  │  → Reads SUBSCRIBE + client's UDP port │  │
  │                   │  │  → Registers (IP, udp_port) in set     │  │
  │                   │  │  → Closes SSL connection (one-shot)    │  │
  │                   │  └────────────────────────────────────────┘  │
  │                   │                                              │
  │   Port 5000       │  ┌────────────────────────────────────────┐  │
  └──UDP Data─────────┤  │  listen_udp() thread                   │  │
     (NOTIFY/ACK/     │  │  → Receives ACK, HEARTBEAT, UNSUBSCRIBE│  │
      HEARTBEAT/      │  └────────────────────────────────────────┘  │
      UNSUBSCRIBE)    │                                              │
                      │  ┌────────────────────────────────────────┐  │
                      │  │  retransmission_thread()               │  │
                      │  │  → Retransmits unACK'd UDP packets     │  │
                      │  │  → Evicts clients silent for 5s        │  │
                      │  └────────────────────────────────────────┘  │
                      └─────────────────┬────────────────────────────┘
                                        │
                     UDP broadcasts (NOTIFY) → all subscribers
                          ┌─────────────┴──────────────┐
                          │                            │
               ┌──────────▼──────────┐    ┌───────────▼─────────┐
               │    CLIENT A          │    │    CLIENT B          │
               │  (client.py)         │    │  (client.py)         │
               │                      │    │                      │
               │ 1. subscribe():      │    │ 1. subscribe():      │
               │    SSL/TCP to :5001  │    │    SSL/TCP to :5001  │
               │    sends UDP port    │    │    sends UDP port    │
               │    → closes SSL      │    │    → closes SSL      │
               │                      │    │                      │
               │ 2. listen() [UDP]:   │    │ 2. listen() [UDP]:   │
               │    recv NOTIFY       │    │    recv NOTIFY       │
               │    → send ACK (UDP)  │    │    → send ACK (UDP)  │
               │                      │    │                      │
               │ 3. heartbeat [UDP]:  │    │ 3. heartbeat [UDP]:  │
               │    ping every 2s     │    │    ping every 2s     │
               └──────────────────────┘    └─────────────────────┘

Topology : Star (1 server ↔ N clients, individual unicast sockets)
Auth     : SSL/TLS (TLS 1.3) on port 5001 — SUBSCRIBE only (one-shot)
Data     : UDP on port 5000 — NOTIFY, ACK, HEARTBEAT, UNSUBSCRIBE
Protocol : Custom binary packet [4B seq | 1B type | 2B len | 2B CRC32] + payload
```

---

## 📦 Custom Packet Format

Every message — whether a SUBSCRIBE, NOTIFY, ACK, HEARTBEAT, or UNSUBSCRIBE — uses
the same 9-byte binary header format defined in `protocol.py`:

```
 0       4   5     7     9         9 + payload_len
 ┌───────────┬──┬──────┬──────┬────────────────────┐
 │ Seq Num   │Ty│ Len  │ CRC  │     Payload        │
 │ (4 bytes) │pe│(2 B) │(2 B) │  (variable length) │
 │ uint32    │(1│uint16│uint16│  UTF-8 string      │
 └───────────┴──┴──────┴──────┴────────────────────┘
```

- **Seq Num**: Monotonically increasing ID for reliable delivery tracking
- **Type**: `1=SUBSCRIBE`, `2=NOTIFY`, `3=ACK`, `4=UNSUBSCRIBE`, `5=HEARTBEAT`
- **Len**: Payload byte count (used by TCP framing helpers)
- **CRC**: 16-bit CRC32 checksum for corruption detection
- **Payload**: For NOTIFY: `"timestamp|message"` (timestamp used for latency calculation)

---

## 🔒 SSL/TLS Security

All communication between the server and clients is encrypted using TLS 1.3
via Python's built-in `ssl` module.

### Certificate Files

| File         | Description                                      |
|--------------|--------------------------------------------------|
| `server.crt` | X.509 self-signed public certificate (shared)    |
| `server.key` | RSA-2048 private key (kept on server only)       |

### Regenerating Certificates

If the certificates expire or are missing, regenerate them with:

```bash
openssl req -x509 -newkey rsa:2048 \
            -keyout server.key \
            -out server.crt \
            -days 365 \
            -nodes \
            -subj '/CN=localhost'
```

> **Note:** The `-nodes` flag skips passphrase encryption on the private key
> (required for non-interactive server startup). For production environments,
> use a CA-signed certificate and enable `ssl.CERT_REQUIRED` on the client.

---

## 🛠️ Requirements

| Requirement | Version / Notes                      |
|-------------|--------------------------------------|
| Python      | 3.8 or higher                        |
| `ssl`       | Built into Python standard library   |
| `socket`    | Built into Python standard library   |
| `struct`    | Built into Python standard library   |
| `zlib`      | Built into Python standard library   |
| `matplotlib`| For performance graph generation     |

Install `matplotlib`:

```bash
pip install matplotlib
```

Verify SSL certificate files exist before starting the server:

```bash
ls -lh server.crt server.key
```

---

## 🚀 The Project Demo

### Method A: The Localhost Demo
*This method proves the entire Hybrid Architecture (TLS + UDP) works perfectly without fighting university firewalls or mobile hotspot AP isolation.*

1. **Open Terminal 1 (The Server)**
   ```bash
   python3 server.py
   ```
2. **Open Terminal 2 (Client 1)**
   ```bash
   python3 client.py
   ```
3. **Open Terminal 3 (Client 2)**
   ```bash
   python3 client.py
   ```
4. **Test the Broadcast**
   Go back to Terminal 1, type `Hello world!` and press Enter. You will instantly see the UDP broadcast hit both clients, and see the ACKs returned to the server.

---

### Method B: Cross-Device Demo (Between Two Laptops)
*Note: This will NOT work on an iPhone/Android Mobile Hotspot or University Wi-Fi due to "Client AP Isolation" hardware firewalls dropping peer-to-peer UDP packets. You MUST be connected to a normal Home Router.*

1. **On Laptop 1 (The Mac/Server):**
   Find your IP Address:
   ```bash
   ipconfig getifaddr en0
   ```
   *(Let's assume it prints `192.168.1.5`)*

   Start the server:
   ```bash
   python3 server.py
   ```

2. **On Laptop 2 (The Windows/Friend's PC):**
   Ensure they have the latest code, then run the client by typing the Mac's IP address directly in the command:
   ```cmd
   python client.py 192.168.1.5
   ```

3. **Test the Broadcast:**
   Type a message on the Mac server, and it will instantly pop up on the Windows laptop securely!

### 5. Run Automated Performance Tests

Runs all tests (0%–30% loss) for both systems and saves the graph:

```bash
python3 test_system.py
```

Output: `performance_results.png` with 4 comparison panels.

---

## 📊 Architecture & Design Decisions

### Why TCP instead of UDP for the Reliable system?

SSL/TLS was designed specifically for stream-oriented (TCP) sockets. While DTLS
(Datagram TLS) exists for UDP, Python's `ssl` module does not natively support it.
Switching to TCP+SSL gives us full encryption with standard library support.

### Why keep ACKs and retransmission on top of TCP?

TCP guarantees bytes arrive at the OS receive buffer. Our application-level ACKs
provide a stronger guarantee: the **client application processed the notification**.
This semantic difference is important for notification systems where silent drops
(app crashed after receive but before processing) would otherwise go undetected.

### Why star topology with unicast?

Unlike multicast (which has router support requirements), unicast over individual
SSL sockets gives us per-client delivery tracking. We know exactly which client
received which message and can retransmit selectively.

---

## 📈 Performance Findings

Tests conducted with 3 clients, 5 notifications per run, at four loss levels:

| Metric           | System       | 0% Loss | 10% Loss | 20% Loss | 30% Loss |
|------------------|--------------|---------|----------|----------|----------|
| Delivery Rate    | Reliable SSL | ~100%   | ~100%    | ~100%    | ~90-100% |
| Delivery Rate    | Plain UDP    | ~100%   | ~80%     | ~65%     | ~50%     |
| Avg Latency      | Reliable SSL | Low     | Moderate | Moderate | High     |
| Avg Latency      | Plain UDP    | Low     | Low      | Low      | Low*     |
| Retransmissions  | Reliable SSL | 0       | Low      | Moderate | High     |

_*Plain UDP latency appears lower at high loss because undelivered messages are
simply not counted — the sample set is smaller and biased toward fast arrivals._

### Key Takeaway

> At 30% packet loss, Plain UDP delivers only **~50% of messages**.
> Our Reliable SSL system maintains **90–100% delivery** — at the cost of
> higher latency due to retransmission wait times. This is the classic
> **reliability vs. latency tradeoff** in network systems design.

---

## 📂 File Overview

| File               | Description                                                        |
|--------------------|--------------------------------------------------------------------|
| `protocol.py`      | Custom binary packet format, CRC checksum, TCP framing helpers     |
| `server.py`        | SSL/TCP notification server with ACK, retransmit, heartbeat        |
| `client.py`        | SSL/TCP subscriber client with listener, heartbeat, latency track  |
| `plain_udp.py`     | Best-effort UDP baseline (no SSL, no ACKs, no retransmission)      |
| `test_system.py`   | Automated testing framework — 4 metrics, 4 loss levels, 4 graphs  |
| `server.crt`       | SSL public certificate (X.509, self-signed, RSA-2048)              |
| `server.key`       | SSL private key (RSA-2048, not encrypted, lab use only)            |
| `performance_results.png` | Output graph from the last test run                         |
