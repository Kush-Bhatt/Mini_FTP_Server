"""UDP Mini-FTP client (ACN Programming Assignment 2, Part 2).

Presents a prompt supporting put / get / list / quit and speaks the same
stop-and-wait reliability protocol as UDPFTPServer.py:

  - control : one ASCII '|'-separated datagram, resent every 0.5 s up to 5x
  - DATA    : 7-byte "!IBH" header (seq, is_last, data_len) + <=1000 bytes
  - ACK     : 4-byte "!I" (seq)
  - stop-and-wait: send a chunk, wait 0.5 s for its ACK, resend on timeout,
    abort a chunk after 10 consecutive timeouts
  - finish  : sender sends DONE|<md5>, receiver replies VERIFIED / MISMATCH

Local-file collision policy for `get`: auto-rename to name_1.ext, name_2.ext
(first free), so an existing local file is never overwritten.

Usage:
    python3 UDPFTPClient.py <server_ip> <server_port>
"""

import hashlib
import os
import random
import socket
import struct
import sys
import time

CHUNK_SIZE = 1000
DATA_HEADER = "!IBH"
DATA_HEADER_LEN = struct.calcsize(DATA_HEADER)    # 7
ACK_FORMAT = "!I"
RECV_BUFSIZE = 1024

SOCK_TIMEOUT = 0.5
HANDSHAKE_RETRIES = 5
MAX_CHUNK_RETRIES = 10
FINISH_ATTEMPTS = MAX_CHUNK_RETRIES + HANDSHAKE_RETRIES + 2

LOSS_RATE = 0.0


# --------------------------------------------------------------------------- #
# Packet build / parse helpers - identical to the server's copies so both
# sides frame every datagram the same way.
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


def drain_socket(sock):
    """Discards every datagram currently buffered on `sock`, without blocking.

    Under packet loss the previous command leaves retransmitted DATA / ACK /
    DONE datagrams queued. If the next command's handshake reads one of those
    instead of the real reply it desyncs (e.g. 'put rejected: DONE|...').
    Draining at the start of each command starts it clean.
    """
    sock.setblocking(False)
    try:
        while True:
            sock.recvfrom(RECV_BUFSIZE)
    except (BlockingIOError, OSError):
        pass
    finally:
        sock.setblocking(True)


def unique_local_path(name):
    """`name` if free, else name_1.ext, name_2.ext, ... (first free)."""
    if not os.path.exists(name):
        return name
    stem, ext = os.path.splitext(name)
    i = 1
    while os.path.exists(f"{stem}_{i}{ext}"):
        i += 1
    return f"{stem}_{i}{ext}"


# --------------------------------------------------------------------------- #
# Control handshake (Requirement 2.1): send, wait 0.5 s, retry up to 5 times.
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
# Stop-and-wait SENDER (Requirement 2.4) - client side of a PUT.
# --------------------------------------------------------------------------- #
def send_file_data(sock, addr, file_bytes, label):
    """Sends file_bytes as stop-and-wait DATA chunks.

    Returns a (total_chunks, retransmitted_chunks, duplicate_acks) tuple once
    every chunk is ACKed, or None if one chunk times out MAX_CHUNK_RETRIES
    times in a row.

      - retransmitted_chunks: one per timeout (a resend of the current chunk)
      - duplicate_acks: ACKs received for a chunk we had already advanced past
        (the receiver's original ACK was slow, so it arrived after we resent
        and got the fresh one) - the sender-side view of duplicate ACKs
    """
    total = total_chunks_for(len(file_bytes))
    sock.settimeout(SOCK_TIMEOUT)

    retransmits = 0
    dup_acks = 0
    seq = 0
    while seq < total:
        chunk = file_bytes[seq * CHUNK_SIZE:(seq + 1) * CHUNK_SIZE]
        is_last = (seq == total - 1)
        packet = make_data_packet(seq, is_last, chunk)

        retries = 0
        while True:                                # (re)send loop for this chunk
            sendto(sock, packet, addr)
            got_ack = False
            while not got_ack:                     # read ACKs until ours or timeout
                try:
                    ack, _ = sock.recvfrom(RECV_BUFSIZE)
                except socket.timeout:
                    retries += 1
                    retransmits += 1
                    if retries >= MAX_CHUNK_RETRIES:
                        print(f"Transfer failed: no ACK for chunk {seq} "
                              f"after {MAX_CHUNK_RETRIES} retries")
                        return None
                    print(f"[{label}] no ACK for chunk {seq} - resending "
                          f"(retry {retries}/{MAX_CHUNK_RETRIES})")
                    break                         # resend the chunk
                if len(ack) != 4:
                    continue                       # not an ACK - ignore
                acked = parse_ack_packet(ack)
                if acked == seq:
                    got_ack = True
                elif acked < seq:
                    dup_acks += 1
                    print(f"[{label}] duplicate ACK for chunk {acked} "
                          f"(already past it) - ignored")
                # acked > seq is impossible under stop-and-wait
            if got_ack:
                break

        if seq % 50 == 0 or is_last:
            print(f"[{label}] sent chunk {seq + 1}/{total}")
        seq += 1

    print(f"[{label}] done: {total} chunks sent, {retransmits} retransmitted, "
          f"{dup_acks} duplicate ACK(s)")
    return total, retransmits, dup_acks


# --------------------------------------------------------------------------- #
# Stop-and-wait RECEIVER (Requirement 2.4) - client side of a GET.
# --------------------------------------------------------------------------- #
def recv_file_data(sock, addr, total_chunks, out_path, label):
    """Receives DATA chunks from addr and writes them, in order, to out_path.

    Returns (chunks_written, duplicate_chunks) once the is_last chunk has
    been received and ACKed. `duplicate_chunks` is how many DATA packets
    arrived that we already had (i.e. sender retransmissions whose ACK was
    lost) - the receiver-side view of retransmissions during a GET.
    """
    expected = 0
    duplicates = 0
    with open(out_path, "wb") as out_file:
        while True:
            sock.settimeout(None)
            packet, sender = sock.recvfrom(RECV_BUFSIZE)
            if sender != addr:
                continue

            seq, is_last, chunk = parse_data_packet(packet)

            if seq == expected:
                out_file.write(chunk)
                out_file.flush()
                sendto(sock, make_ack_packet(seq), addr)
                expected += 1
                if expected % 50 == 0 or is_last:
                    print(f"[{label}] received chunk {expected}/{total_chunks}")
                if is_last:
                    return expected, duplicates
            elif seq < expected:
                duplicates += 1
                print(f"[{label}] duplicate chunk {seq} - re-sending ACK")
                sendto(sock, make_ack_packet(seq), addr)
            else:
                print(f"[{label}] out-of-order chunk {seq} "
                      f"(expected {expected}) - dropped")


def finish_as_receiver(sock, addr, local_path):
    """After recv_file_data: wait for the sender's DONE|<md5>, verify, reply.

    Returns the verdict string, or None on giving up. Under loss this must
    survive: a retransmitted last DATA chunk (re-ACK it), and a lost verdict
    where the server keeps resending DONE (re-send our reply each time).
    """
    our_md5 = md5_of_file(local_path)
    sock.settimeout(SOCK_TIMEOUT)
    verdict = None
    for _ in range(FINISH_ATTEMPTS):
        try:
            packet, sender = sock.recvfrom(RECV_BUFSIZE)
        except socket.timeout:
            if verdict is not None:
                return verdict         # replied already, server went quiet
            continue
        if sender != addr:
            continue

        text = packet.decode("ascii", errors="replace")
        if text.startswith("DONE|"):
            if verdict is None:                       # compare once
                verdict = ("VERIFIED" if text.split("|", 1)[1] == our_md5
                           else "MISMATCH")
            sendto(sock, verdict.encode("ascii"), addr)   # (re)send reply
            continue
        try:                                          # duplicate last chunk
            seq, _, _ = parse_data_packet(packet)
            sendto(sock, make_ack_packet(seq), addr)
        except struct.error:
            pass
    return verdict


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def do_list(sock, server):
    """LIST: one handshake round-trip, then unpack OK|count|name,size;..."""
    drain_socket(sock)                    # clear any leftovers from a prior transfer
    reply = send_and_await_reply(sock, "LIST", server)
    if reply is None:
        print("list: no response from server")
        return
    if not reply.startswith("OK|"):
        print(f"list failed: {reply}")
        return
    _, count, blob = reply.split("|", 2)
    print(f"{count} file(s) on server:")
    for item in blob.split(";"):
        if item:
            name, size = item.split(",")
            print(f"  {name} {size}")


def do_put(sock, server, local_path):
    """Uploads a local file: handshake -> send chunks -> DONE / verdict."""
    if not os.path.isfile(local_path):
        print(f"put: local file not found: {local_path}")
        return
    # A leftover 'DONE|<md5>' from a previous lossy transfer would otherwise
    # be read as this handshake's reply -> "put rejected: DONE|...".
    drain_socket(sock)
    with open(local_path, "rb") as f:
        data = f.read()
    name = os.path.basename(local_path)
    total = total_chunks_for(len(data))

    reply = send_and_await_reply(
        sock, f"PUT|{name}|{len(data)}|{total}", server)
    if reply is None:
        print("put: no response to handshake")
        return
    if not reply.startswith("READY"):
        print(f"put rejected: {reply}")
        return

    print(f"Uploading {name} ({len(data)} bytes, {total} chunks)...")
    start = time.time()
    result = send_file_data(sock, server, data, name)
    if result is None:
        return                                    # aborted at 10 retries
    total_chunks, retransmits, dup_acks = result
    elapsed = time.time() - start

    verdict = send_and_await_reply(
        sock, f"DONE|{hashlib.md5(data).hexdigest()}", server)
    rate = len(data) / elapsed / 1024 if elapsed else 0.0
    print(f"Upload complete: {name} -> {verdict}\n"
          f"  file size          : {len(data)} bytes\n"
          f"  chunks transferred : {total_chunks}\n"
          f"  chunks retransmitted: {retransmits}\n"
          f"  duplicate ACKs seen : {dup_acks}\n"
          f"  transfer time      : {elapsed:.2f} s\n"
          f"  throughput         : {rate:.1f} KiB/s")


def do_get(sock, server, remote_name):
    """Downloads a file: handshake -> receive chunks -> verify DONE."""
    # A stale DATA/ACK/DONE from a previous transfer would be mis-read as the
    # GET handshake reply -> "get failed: <binary garbage>".
    drain_socket(sock)
    reply = send_and_await_reply(sock, f"GET|{remote_name}|0", server)
    if reply is None:
        print("get: no response to handshake")
        return
    if not reply.startswith("READY"):
        print(f"get failed: {reply}")             # e.g. ERROR|file not found
        return

    try:
        _, size_text, chunks_text = reply.split("|")
    except ValueError:
        print(f"get failed: unexpected reply {reply!r}")
        return
    filesize, total = int(size_text), int(chunks_text)
    local_path = unique_local_path(os.path.basename(remote_name))
    print(f"Downloading {remote_name} ({filesize} bytes, {total} chunks) "
          f"-> {local_path}")

    start = time.time()
    chunks_written, duplicates = recv_file_data(
        sock, server, total, local_path, os.path.basename(local_path))
    elapsed = time.time() - start

    verdict = finish_as_receiver(sock, server, local_path)
    rate = filesize / elapsed / 1024 if elapsed else 0.0
    print(f"Download complete: {local_path} -> {verdict}\n"
          f"  file size          : {filesize} bytes\n"
          f"  chunks transferred : {chunks_written}\n"
          f"  duplicate chunks   : {duplicates}  (sender retransmissions seen)\n"
          f"  transfer time      : {elapsed:.2f} s\n"
          f"  throughput         : {rate:.1f} KiB/s")


def command_loop(sock, server):
    """Reads user commands and dispatches them until 'quit' or EOF."""
    while True:
        try:
            raw = input("udp-ftp> ").strip()
        except EOFError:
            break
        if not raw:
            continue

        parts = raw.split(" ", 1)
        verb = parts[0].lower()
        arg = parts[1].strip() if len(parts) == 2 else ""

        if verb == "quit":
            break

        try:
            if verb == "list":
                do_list(sock, server)
            elif verb == "put":
                do_put(sock, server, arg) if arg else print(
                    "usage: put <local_filename>")
            elif verb == "get":
                do_get(sock, server, arg) if arg else print(
                    "usage: get <remote_filename>")
            else:
                print(f"unknown command: {verb!r} "
                      f"(try: put, get, list, quit)")
        except (OSError, struct.error, ValueError) as err:
            print(f"command failed: {err}")


def main():
    """Parses server_ip / server_port and runs the prompt."""
    global LOSS_RATE

    args = sys.argv[1:]
    if "--loss-rate" in args:
        i = args.index("--loss-rate")
        LOSS_RATE = float(args[i + 1])
        del args[i:i + 2]

    if len(args) != 2:
        print("Usage: python3 UDPFTPClient.py <server_ip> <server_port> ")
        sys.exit(1)
    try:
        server = (args[0], int(args[1]))
    except ValueError:
        print("Port must be an integer.")
        sys.exit(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"UDP Mini-FTP client -> {server[0]}:{server[1]} . Commands: put | get | list | quit")
    try:
        command_loop(sock, server)
    finally:
        sock.close()
        print("Bye.")


if __name__ == "__main__":
    main()
