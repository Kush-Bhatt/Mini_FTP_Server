"""UDP Mini-FTP server (ACN Programming Assignment 2, Part 2).

Repeats the PUT / GET / LIST functionality of Part 1 over UDP with a
stop-and-wait reliability layer (timeouts, ACKs, retransmission) built on
top of the unreliable datagram transport.

One UDP socket on a well-known port serves every client; a client is
identified by the (IP, port) tuple from recvfrom(). Transfers are handled
one at a time - while one is in progress, a datagram from any other address
is discarded and that client's handshake retry covers the wait.

Protocol:
  - control : one ASCII '|'-separated datagram, resent every 0.5 s up to 5x
  - DATA    : 7-byte "!IBH" header (seq, is_last, data_len) + <=1000 bytes
  - ACK     : 4-byte "!I" (seq)
  - finish  : sender sends DONE|<md5>, receiver replies VERIFIED / MISMATCH

Usage:
    python3 UDPFTPServer.py <port>                     # port > 10000
    python3 UDPFTPServer.py <port> --loss-rate 0.1     # dev-only packet drop
"""

import hashlib
import os
import random
import socket
import struct
import sys

STORAGE_DIR = "server_storage"

# Requirement 2.2: 1000-byte file chunks behind a 7-byte binary header.
CHUNK_SIZE = 1000
DATA_HEADER = "!IBH"                              # seq (I), is_last (B), data_len (H)
DATA_HEADER_LEN = struct.calcsize(DATA_HEADER)    # 7
ACK_FORMAT = "!I"                                 # seq
RECV_BUFSIZE = 1024                               # 7 + 1000 = 1007 fits under this

# Requirement 2.1 / 2.4
SOCK_TIMEOUT = 0.5          # required default socket timeout, seconds
HANDSHAKE_RETRIES = 5      # control messages: resend up to 5 times
MAX_CHUNK_RETRIES = 10    # data chunks: abort after 10 consecutive timeouts

# Iterations spent waiting for DONE after a receive: enough to absorb a
# worst-case burst of last-chunk retransmissions plus DONE resends.
FINISH_ATTEMPTS = MAX_CHUNK_RETRIES + HANDSHAKE_RETRIES + 2

# Requirement 2.6: application-layer loss injection, local development only.
# Kept at 0.0 for graded runs (real loss is injected with `tc netem`).
LOSS_RATE = 0.0


# --------------------------------------------------------------------------- #
# Packet build / parse helpers (Requirements 2.2, 2.3)
# --------------------------------------------------------------------------- #
def total_chunks_for(filesize):
    """Number of 1000-byte chunks a file splits into (an empty file is 1)."""
    if filesize == 0:
        return 1
    return (filesize + CHUNK_SIZE - 1) // CHUNK_SIZE


def make_data_packet(seq_num, is_last, chunk_bytes):
    """Builds a DATA datagram: 7-byte header + up to 1000 payload bytes."""
    header = struct.pack(DATA_HEADER, seq_num, 1 if is_last else 0,
                         len(chunk_bytes))
    return header + chunk_bytes


def parse_data_packet(packet):
    """Splits a DATA datagram into (seq_num, is_last, chunk_bytes)."""
    seq_num, is_last, data_len = struct.unpack(
        DATA_HEADER, packet[:DATA_HEADER_LEN])
    chunk_bytes = packet[DATA_HEADER_LEN:DATA_HEADER_LEN + data_len]
    return seq_num, is_last, chunk_bytes


def make_ack_packet(seq_num):
    """Builds a 4-byte ACK datagram for seq_num."""
    return struct.pack(ACK_FORMAT, seq_num)


def parse_ack_packet(packet):
    """Returns the sequence number carried by a 4-byte ACK datagram."""
    return struct.unpack(ACK_FORMAT, packet)[0]


def md5_of_file(path):
    """Returns the hex MD5 digest of the file at `path` (read in blocks)."""
    digest = hashlib.md5()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def should_drop():
    """True when this outgoing packet should be dropped (dev loss testing)."""
    return LOSS_RATE > 0.0 and random.random() < LOSS_RATE


def sendto(sock, packet, addr):
    """sendto() wrapper that honours the dev-only LOSS_RATE."""
    if should_drop():
        return
    sock.sendto(packet, addr)


def safe_path(name):
    """Maps a client filename to a path inside STORAGE_DIR (None if unusable).

    Only the base name is kept, so '../x' or '/etc/y' cannot escape.
    """
    base = os.path.basename(name.strip())
    if not base or base in (".", ".."):
        return None
    return os.path.join(STORAGE_DIR, base)


# --------------------------------------------------------------------------- #
# Control handshake (Requirement 2.1): send, wait 0.5 s, retry up to 5 times.
# Used by the server only for the DONE step it initiates during a GET.
# --------------------------------------------------------------------------- #
def send_and_await_reply(sock, message, addr):
    """Sends an ASCII control message; returns the reply string or None."""
    sock.settimeout(SOCK_TIMEOUT)
    for _ in range(HANDSHAKE_RETRIES):
        sendto(sock, message.encode("ascii"), addr)
        try:
            reply, _ = sock.recvfrom(RECV_BUFSIZE)
            return reply.decode("ascii", errors="replace")
        except socket.timeout:
            continue
    return None


# --------------------------------------------------------------------------- #
# Stop-and-wait SENDER (Requirement 2.4) - server side of a GET.
# --------------------------------------------------------------------------- #
def send_file_data(sock, addr, file_bytes, label):
    """Sends file_bytes as stop-and-wait DATA chunks.

    Returns True once every chunk is ACKed, or False if one chunk times out
    MAX_CHUNK_RETRIES times in a row.
    """
    total = total_chunks_for(len(file_bytes))
    sock.settimeout(SOCK_TIMEOUT)

    seq = 0
    while seq < total:
        chunk = file_bytes[seq * CHUNK_SIZE:(seq + 1) * CHUNK_SIZE]
        is_last = (seq == total - 1)
        packet = make_data_packet(seq, is_last, chunk)

        retries = 0
        while True:
            sendto(sock, packet, addr)
            try:
                ack, _ = sock.recvfrom(RECV_BUFSIZE)
            except socket.timeout:
                retries += 1
                if retries >= MAX_CHUNK_RETRIES:
                    print(f"Transfer failed: no ACK for chunk {seq} "
                          f"after {MAX_CHUNK_RETRIES} retries")
                    return False
                continue                       # resend the same packet
            if len(ack) == 4 and parse_ack_packet(ack) == seq:
                break                          # correct ACK - advance

        if seq % 50 == 0 or is_last:
            print(f"[{label}] sent chunk {seq + 1}/{total}")
        seq += 1

    return True


# --------------------------------------------------------------------------- #
# Stop-and-wait RECEIVER (Requirement 2.4) - server side of a PUT.
# --------------------------------------------------------------------------- #
def recv_file_data(sock, addr, total_chunks, out_path, label):
    """Receives DATA chunks from addr and writes them, in order, to out_path.

    Returns once the is_last chunk has been received and ACKed.
    """
    expected = 0
    with open(out_path, "wb") as out_file:
        while True:
            sock.settimeout(None)                     # receiver never times out
            packet, sender = sock.recvfrom(RECV_BUFSIZE)
            if sender != addr:
                continue                              # not our transfer partner

            seq, is_last, chunk = parse_data_packet(packet)

            if seq == expected:                       # the chunk we wanted
                out_file.write(chunk)
                out_file.flush()
                sendto(sock, make_ack_packet(seq), addr)
                expected += 1
                if expected % 50 == 0 or is_last:
                    print(f"[{label}] received chunk {expected}/{total_chunks}")
                if is_last:
                    return
            elif seq < expected:                      # duplicate - re-ACK only
                print(f"[{label}] duplicate chunk {seq} - re-sending ACK")
                sendto(sock, make_ack_packet(seq), addr)
            else:                                     # seq > expected
                # Unreachable under correct stop-and-wait; per spec, drop it
                # and send no ACK so the sender retransmits `expected`.
                print(f"[{label}] out-of-order chunk {seq} "
                      f"(expected {expected}) - dropped")


def finish_as_receiver(sock, addr, path):
    """After recv_file_data: wait for DONE|<md5>, reply VERIFIED / MISMATCH.

    A retransmitted last DATA chunk (its ACK was lost) is re-ACKed here so
    the sender can move on to sending DONE.
    """
    sock.settimeout(SOCK_TIMEOUT)
    for _ in range(FINISH_ATTEMPTS):
        try:
            packet, sender = sock.recvfrom(RECV_BUFSIZE)
        except socket.timeout:
            continue
        if sender != addr:
            continue

        text = packet.decode("ascii", errors="replace")
        if text.startswith("DONE|"):
            client_md5 = text.split("|", 1)[1]
            verdict = ("VERIFIED" if md5_of_file(path) == client_md5
                       else "MISMATCH")
            sendto(sock, verdict.encode("ascii"), addr)
            print(f"[+] {os.path.basename(path)} {verdict}")
            return
        try:                                          # duplicate last chunk
            seq, _, _ = parse_data_packet(packet)
            sendto(sock, make_ack_packet(seq), addr)
        except struct.error:
            pass


# --------------------------------------------------------------------------- #
# Per-request handlers
# --------------------------------------------------------------------------- #
def handle_list(sock, addr):
    """LIST -> one datagram: OK|<count>|name1,size1;name2,size2;..."""
    items = []
    for name in sorted(os.listdir(STORAGE_DIR)):
        path = os.path.join(STORAGE_DIR, name)
        if os.path.isfile(path):
            items.append(f"{name},{os.path.getsize(path)}")
    reply = f"OK|{len(items)}|" + ";".join(items)
    sendto(sock, reply.encode("ascii"), addr)
    print(f"[+] {addr} LIST -> {len(items)} file(s)")


def handle_put(sock, addr, fields):
    """PUT|name|size|chunks -> READY|0, then receive + MD5 verify."""
    if len(fields) != 4:
        sendto(sock, b"ERROR|malformed PUT", addr)
        return
    path = safe_path(fields[1])
    if path is None:
        sendto(sock, b"ERROR|invalid filename", addr)
        return
    try:
        filesize = int(fields[2])            # fields[3] (chunks) is recomputed
    except ValueError:
        sendto(sock, b"ERROR|invalid filesize", addr)
        return

    print(f"[+] {addr} uploading {os.path.basename(path)} ({filesize} bytes)")
    sendto(sock, b"READY|0", addr)

    recv_file_data(sock, addr, total_chunks_for(filesize), path,
                   os.path.basename(path))
    finish_as_receiver(sock, addr, path)


def handle_get(sock, addr, fields):
    """GET|name|0 -> READY|size|chunks, then send + announce DONE|<md5>."""
    if len(fields) < 2:
        sendto(sock, b"ERROR|malformed GET", addr)
        return
    path = safe_path(fields[1])
    if path is None or not os.path.isfile(path):
        sendto(sock, b"ERROR|file not found", addr)
        print(f"[-] {addr} GET {fields[1]!r} - not found")
        return

    filesize = os.path.getsize(path)
    total = total_chunks_for(filesize)
    print(f"[+] {addr} downloading {os.path.basename(path)} ({filesize} bytes)")
    sendto(sock, f"READY|{filesize}|{total}".encode("ascii"), addr)

    with open(path, "rb") as f:
        file_bytes = f.read()

    if not send_file_data(sock, addr, file_bytes, os.path.basename(path)):
        return                                    # aborted at 10 retries

    verdict = send_and_await_reply(sock, f"DONE|{md5_of_file(path)}", addr)
    print(f"[+] {os.path.basename(path)} -> client says {verdict}")


def dispatch(sock, addr, packet):
    """Routes one freshly received control datagram to its handler."""
    fields = packet.decode("ascii", errors="replace").split("|")
    command = fields[0]
    if command == "LIST":
        handle_list(sock, addr)
    elif command == "PUT":
        handle_put(sock, addr, fields)
    elif command == "GET":
        handle_get(sock, addr, fields)
    # A stray DATA/ACK/DONE with no active transfer decodes to nothing
    # useful here and is ignored.


def main():
    """Parses args, binds one UDP socket, runs the recvfrom dispatch loop."""
    global LOSS_RATE

    args = sys.argv[1:]
    if "--loss-rate" in args:                     # Requirement 2.6
        i = args.index("--loss-rate")
        LOSS_RATE = float(args[i + 1])
        del args[i:i + 2]

    if len(args) != 1:
        print("Usage: python3 UDPFTPServer.py <port> [--loss-rate R]")
        sys.exit(1)
    try:
        port = int(args[0])
    except ValueError:
        print("Port must be an integer.")
        sys.exit(1)
    if port <= 10000:
        print("Please choose a port number greater than 10000.")
        sys.exit(1)

    os.makedirs(STORAGE_DIR, exist_ok=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", port))
    print(f"[*] UDP Mini-FTP server on port {port} (loss-rate {LOSS_RATE})")

    try:
        while True:
            sock.settimeout(None)
            packet, addr = sock.recvfrom(RECV_BUFSIZE)
            try:
                dispatch(sock, addr, packet)
            except (OSError, struct.error, ValueError) as err:
                print(f"[-] {addr} request failed: {err}")
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
