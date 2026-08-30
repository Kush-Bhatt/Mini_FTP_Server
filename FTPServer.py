"""Mini-FTP server over TCP (ACN Programming Assignment 2, Part 1).

Implements the PUT, GET, LIST and QUIT commands from the assignment's
message-format table. Each client connection is served in its own thread
so that multiple clients can upload/download at the same time without
blocking each other.

Wire protocol (one ASCII line terminated by '\\n', then optional payload):

    PUT <filename> <filesize>\\n + <filesize> bytes  ->  OK <filesize>\\n | ERR <reason>\\n
    GET <filename>\\n                                ->  OK <filesize>\\n + <filesize> bytes | ERR <reason>\\n
    LIST\\n                                          ->  OK <count>\\n + <count> lines "<name> <size>\\n"
    QUIT\\n                                          ->  (server closes the connection)

Usage:
    python3 FTPServer.py <port>        # choose a port > 10000
"""

import os
import socket
import sys
import threading

# Requirement 1.1: all files live inside this single sub-directory and the
# server must never read or write anything outside it.
STORAGE_DIR = "server_storage"

# Upper bound for a single recv() call. recv() may return fewer bytes; the
# helpers below loop until they have what the protocol needs.
RECV_CHUNK = 4096


# --------------------------------------------------------------------------- #
# Stream framing helpers
#
# Requirement 1.3: TCP is a byte stream with no message boundaries, so a
# single recv() is NOT guaranteed to return a whole line or a whole file.
# recv_line() reads byte increments until it sees '\n'; recv_exact() loops
# recv() until exactly <filesize> bytes have been accumulated. Both carry a
# `buffer` of bytes already received but not yet consumed and return it so
# the caller can pass leftovers on to the next read.
# --------------------------------------------------------------------------- #
def send_line(conn, text):
    """Sends one ASCII response line, appending the '\\n' terminator."""
    conn.sendall((text + "\n").encode("ascii"))


def recv_line(conn, buffer):
    """Reads one '\\n'-terminated command/response line.

    Args:
        conn: Connected TCP socket.
        buffer: Bytes received earlier but not yet consumed.

    Returns:
        (line, leftover) - `line` is the decoded text without the trailing
        '\\n'; `leftover` holds any bytes that arrived after the newline
        (start of a payload or of the next command).

    Raises:
        ConnectionError: The peer closed before a full line was received.
    """
    while b"\n" not in buffer:
        data = conn.recv(RECV_CHUNK)
        if not data:
            raise ConnectionError("connection closed while reading a line")
        buffer += data

    line, _, leftover = buffer.partition(b"\n")
    line = line.decode("ascii", errors="replace").rstrip("\r")
    return line, leftover


def recv_exact(conn, num_bytes, buffer):
    """Reads exactly num_bytes bytes, consuming already-buffered bytes first.

    Args:
        conn: Connected TCP socket.
        num_bytes: Total number of payload bytes to return.
        buffer: Bytes received earlier but not yet consumed.

    Returns:
        (payload, leftover) - `payload` is exactly num_bytes long.

    Raises:
        ConnectionError: The peer disconnected before num_bytes arrived
            (Requirement 1.4: client killed mid-transfer).
    """
    payload = buffer[:num_bytes]
    buffer = buffer[num_bytes:]
    while len(payload) < num_bytes:
        data = conn.recv(min(RECV_CHUNK, num_bytes - len(payload)))
        if not data:
            raise ConnectionError("connection closed mid-transfer")
        payload += data
    return payload, buffer


def resolve_in_storage(filename):
    """Maps a client-supplied filename to a safe path inside STORAGE_DIR.

    Requirement 1.1: the server must never touch files outside its storage
    directory. Only the base name is kept, so inputs such as
    '../../etc/passwd' or '/tmp/x' cannot escape.

    Returns:
        A path string inside STORAGE_DIR, or None if the name is unusable.
    """
    safe_name = os.path.basename(filename.strip())
    if not safe_name or safe_name in (".", ".."):
        return None
    return os.path.join(STORAGE_DIR, safe_name)


# --------------------------------------------------------------------------- #
# Command handlers. Each logs an informative line for every action it takes
# (Requirement 1.1: the TA must see what the server did from its console).
# --------------------------------------------------------------------------- #
def handle_list(conn, peer):
    """Handles LIST: replies OK <count> then one '<name> <size>' line each."""
    entries = []
    for name in sorted(os.listdir(STORAGE_DIR)):
        path = os.path.join(STORAGE_DIR, name)
        if os.path.isfile(path):
            entries.append((name, os.path.getsize(path)))

    send_line(conn, f"OK {len(entries)}")
    for name, size in entries:
        send_line(conn, f"{name} {size}")
    print(f"[+] {peer} listed {len(entries)} file(s)")


def handle_get(conn, peer, args):
    """Handles GET <filename>: replies OK <size> + bytes, or ERR file not found."""
    if len(args) != 1:
        send_line(conn, "ERR malformed GET command")
        return

    path = resolve_in_storage(args[0])
    if path is None or not os.path.isfile(path):
        # Requirement 1.4: GET for a missing file -> "ERR file not found".
        send_line(conn, "ERR file not found")
        print(f"[-] {peer} GET {args[0]!r} - not found")
        return

    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as err:
        send_line(conn, f"ERR disk read failed: {err.strerror}")
        return

    print(f"[+] {peer} downloading {os.path.basename(path)} ({len(data)} bytes)")
    send_line(conn, f"OK {len(data)}")
    conn.sendall(data)
    print(f"[+] Sent {os.path.basename(path)}")


def handle_put(conn, peer, args, buffer):
    """Handles PUT <filename> <filesize>: stores the payload, replies OK/ERR.

    Returns the leftover buffer (bytes received past this payload).
    """
    if len(args) != 2:
        send_line(conn, "ERR malformed PUT command")
        return buffer

    filename, size_text = args
    try:
        filesize = int(size_text)
        if filesize < 0:
            raise ValueError
    except ValueError:
        send_line(conn, "ERR invalid filesize")
        return buffer

    path = resolve_in_storage(filename)
    if path is None:
        send_line(conn, "ERR invalid filename")
        return buffer

    print(f"[+] {peer} uploading {os.path.basename(path)} ({filesize} bytes)")

    # Requirement 1.4: if the client disconnects mid-transfer, discard the
    # partial upload, log it, and let handle_client close this socket. Other
    # clients keep being served.
    try:
        data, buffer = recv_exact(conn, filesize, buffer)
    except ConnectionError:
        print(f"[-] {peer} disconnected mid-upload - discarding partial "
              f"{os.path.basename(path)}")
        raise

    # Requirement 1.4: if the disk write fails, reply "ERR <reason>".
    try:
        with open(path, "wb") as f:
            f.write(data)
    except OSError as err:
        send_line(conn, f"ERR disk write failed: {err.strerror}")
        print(f"[-] Failed to save {os.path.basename(path)}: {err}")
        return buffer

    send_line(conn, f"OK {filesize}")
    print(f"[+] Saved {os.path.basename(path)}")
    return buffer


def handle_client(conn, addr):
    """Serves one client connection until QUIT or disconnect.

    Runs in its own thread (Requirement 1.1: concurrent server). One
    exception here never affects the main accept loop or other clients.

    Args:
        conn: The per-client TCP socket returned by accept().
        addr: The client's (ip, port) tuple, used for logging.
    """
    peer = f"{addr[0]}:{addr[1]}"
    print(f"[+] {peer} connected")
    buffer = b""
    try:
        while True:
            # A disconnect *between* commands is a normal client exit; end
            # this thread quietly rather than logging it as an error.
            try:
                line, buffer = recv_line(conn, buffer)
            except ConnectionError:
                break

            if not line:
                continue

            parts = line.split(" ")
            command = parts[0].upper()
            args = parts[1:]

            if command == "QUIT":
                break
            elif command == "PUT":
                buffer = handle_put(conn, peer, args, buffer)
            elif command == "GET":
                handle_get(conn, peer, args)
            elif command == "LIST":
                handle_list(conn, peer)
            else:
                send_line(conn, "ERR unknown command")
    except ConnectionError as err:
        # Reached only on a disconnect *during* a transfer.
        print(f"[-] {peer} connection lost ({err})")
    except OSError as err:
        print(f"[-] {peer} socket error ({err})")
    finally:
        conn.close()
        print(f"[-] {peer} disconnected")


def main():
    """Parses the port argument and runs the accept loop."""
    if len(sys.argv) != 2:
        print("Usage: python3 FTPServer.py <port>")
        sys.exit(1)

    try:
        port = int(sys.argv[1])
    except ValueError:
        print("Port must be an integer.")
        sys.exit(1)

    # Requirement 1.1: choose a port > 10000.
    if port <= 10000:
        print("Please choose a port number greater than 10000.")
        sys.exit(1)

    # Requirement 1.1: create the storage directory at startup if absent.
    os.makedirs(STORAGE_DIR, exist_ok=True)
    print(f"[*] Storage directory: {os.path.abspath(STORAGE_DIR)}")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Requirement 1.1: SO_REUSEADDR so the server can be restarted quickly
    # during testing without waiting out the kernel's TIME_WAIT period.
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_sock.bind(("", port))          # "" -> all local interfaces
        server_sock.listen(16)
        print(f"[*] Mini-FTP server listening on port {port}")

        while True:
            conn, addr = server_sock.accept()
            # Requirement 1.1: threading pattern - hand each client to its
            # own thread so transfers do not block one another.
            thread = threading.Thread(
                target=handle_client, args=(conn, addr), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()
