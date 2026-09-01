"""
protocol.py
Author: Aditya Raj
Description:
    This file serves as the universal language translation layer for our project.
    Why does this file exist?
    If the server and the client had even slightly different definitions of how
    binary data should be packed, the entire system would crash. By isolating
    all the encoding, decoding, and TCP stream logic into this one central file,
    we guarantee that both sides speak the exact same binary language.

    UDP is a datagram protocol (it preserves message boundaries natively).
    However, we use TCP for our SSL security handshake. TCP is a "stream" protocol,
    meaning it can artificially chop up or merge packets over the network.
    Therefore, this file also contains crucial helper functions (recv_exact, recv_packet)
    to safely extract fixed-size packets out of an unpredictable TCP stream.
"""

import struct  # Python standard library to pack/unpack Python data into C-style raw binary bytes
import zlib    # Math library used to compute the CRC32 checksum for detecting data corruption

# ─────────────────────────────────────────────
# Message Type Constants
# These 1-byte labels tell the recipient exactly how to process the incoming packet.
# ─────────────────────────────────────────────
TYPE_SUBSCRIBE   = 1    # Client -> Server: "I want to join. Here is my UDP port."
TYPE_NOTIFY      = 2    # Server -> Client: "Here is a new notification blast for you."
TYPE_ACK         = 3    # Client -> Server: "I successfully received your notification."
TYPE_UNSUBSCRIBE = 4    # Client -> Server: "Please remove me from the broadcast list."
TYPE_HEARTBEAT   = 5    # Client -> Server: "Ping! I am still online and connected."

# ─────────────────────────────────────────────
# Packet Header Format Design
# Format string "!IBHH" defines our strict 9-byte header blueprint:
#   ! = Network Byte Order (Big-Endian — the universal standard for internet data)
#   I = Sequence Number       (4 bytes - Unsigned Integer. Monotonically tracks message order)
#   B = Message Type          (1 byte  - Unsigned Byte. e.g., TYPE_SUBSCRIBE)
#   H = Payload Length        (2 bytes - Unsigned Short. How many bytes is the actual message?)
#   H = Checksum Number       (2 bytes - Unsigned Short. The CRC math fingerprint)
# Total size header = 9 bytes long.
# ─────────────────────────────────────────────
HEADER_FORMAT = "!IBHH"
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)  # Automatically calculates = 9 bytes


def calculate_checksum(data):
    """
    Creates a mathematical fingerprint (CRC) of the packet data.
    Why does this exist?
    If even a single bit of our data flips from 0 to 1 while traveling over Wi-Fi, 
    this returned fingerprint will radically change. The receiver compares fingerprints
    to instantly detect and reject corrupted packets.
    """
    # zlib.crc32 generates a 32-bit hash. 
    # We use '& 0xFFFF' (bitwise AND) to mask and shrink it down to 16-bits 
    # so that it perfectly fits into our 2-byte 'H' header field.
    return zlib.crc32(data) & 0xFFFF  


def encode_packet(seq_num, msg_type, payload):
    """
    Transforms human-readable parameters into a sealed binary capsule ready for network transit.

    Logical Step-by-Step Flow:
      1. Convert the human string into raw UTF-8 computer bytes.
      2. Construct a 'partial' header containing just the sequence, type, and length.
      3. Feed the partial header and the UTF-8 payload through our checksum math algorithm.
      4. Repack the full 9-byte header now including the calculated checksum.
      5. Combine the final header and payload payload bytes and return it.
    """
    # Convert payload to bytes if it's a string. If it's already bytes, leave it alone.
    payload_bytes = payload.encode('utf-8') if isinstance(payload, str) else payload
    payload_len = len(payload_bytes)

    # Step 2: Pack a temporary partial header (missing the checksum)
    header_partial = struct.pack("!IBH", seq_num, msg_type, payload_len)

    # Step 3: Compute the mathematical fingerprint over the entire length of the data
    checksum = calculate_checksum(header_partial + payload_bytes)

    # Step 4: Pack the full, sealed capsule header
    full_header = struct.pack(HEADER_FORMAT, seq_num, msg_type, payload_len, checksum)

    # Step 5: Return the glued-together header and message
    return full_header + payload_bytes


def decode_packet(packet_bytes):
    """
    Receives raw 0s and 1s out of the socket and unpacks them back into usable variables.
    
    Returns: (SequenceNumber, MessageType, ActualPayloadString, isValidBoolean)
    
    'is_valid' will be flagged as False if:
      - The arriving array of bytes is shorter than 9 bytes (a truncated/broken packet).
      - The locally calculated checksum fingerprint doesn't match the sender's stamped checksum.
    """
    # Guard against truncated packets that are too small to even contain a full header
    if len(packet_bytes) < HEADER_SIZE:
        return None, None, None, False

    # Physically slice the binary array into "header" and "payload" chunks
    header_bytes  = packet_bytes[:HEADER_SIZE]   
    payload_bytes = packet_bytes[HEADER_SIZE:]  

    # Unpack the 9 bytes back into our 4 explicit variables based on the "!IBHH" format
    seq_num, msg_type, payload_len, received_checksum = struct.unpack(HEADER_FORMAT, header_bytes)

    # Re-run the mathematical fingerprint check on the received data locally
    header_partial       = struct.pack("!IBH", seq_num, msg_type, payload_len)
    calculated_checksum  = calculate_checksum(header_partial + payload_bytes)

    # If our calculated math matches the math stamped by the sender, the packet arrived unharmed!
    is_valid = (received_checksum == calculated_checksum)

    try:
        # Attempt to decode the binary payload back into a human-readable UTF-8 string
        payload = payload_bytes.decode('utf-8')  
    except UnicodeDecodeError:
        # If the payload was purely binary data, leave it as raw bytes
        payload = payload_bytes

    return seq_num, msg_type, payload, is_valid


# ─────────────────────────────────────────────
# TCP STREAM HANDLING FUNCTIONS (CRITICAL SAFETY MECHANISM)
# 
# Why do we need these?
# Because TCP acts like a continuous stream of water. If you send a 50-byte packet 
# and a 20-byte packet, the OS might smash them together and give you a 70-byte puddle.
# If you run `recv(4096)`, you will grab merged packets and corrupt the decoding logic.
# These helper functions forcefully intercept the stream and guarantee we extract
# exactly one packet at a time.
# ─────────────────────────────────────────────

def recv_exact(sock, n):
    """
    Creates a 'bucket' that loops endlessly, catching drops of incoming TCP data.
    It ONLY returns when the bucket has captured exactly 'n' bytes. No more, no less.
    """
    data = b""              
    while len(data) < n:
        # Only ask the socket for the EXACT remaining number of bytes we need
        chunk = sock.recv(n - len(data))
        if not chunk:
            # If recv returns nothing, the other computer disconnected unexpectedly
            raise ConnectionError("Connection dropped mid-stream.")
        data += chunk       
    return data


def recv_packet(sock):
    """
    The master stream extractor.
    Step 1: Uses recv_exact to read EXACTLY 9 bytes (The Header).
    Step 2: Peeks inside the header to find the `payload_length` value.
    Step 3: Uses recv_exact a second time to read EXACTLY the payload amount.
    This guarantees we slice perfect packets out of an unpredictable TCP stream.
    """
    # Step 1: Forcefully pull exactly 9 bytes off the wire
    header_bytes = recv_exact(sock, HEADER_SIZE)

    # Step 2: Unpack the header just to find out how big the attached message is
    _, _, payload_len, _ = struct.unpack(HEADER_FORMAT, header_bytes)

    # Step 3: Forcefully pull exactly the payload length off the wire
    payload_bytes = recv_exact(sock, payload_len) if payload_len > 0 else b""

    # Step 4: Stitch them together and run them through our standard decoder
    return decode_packet(header_bytes + payload_bytes)
