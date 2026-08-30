"""Mini-FTP client over TCP (ACN Programming Assignment 2, Part 1).

Connects to an FTPServer (Requirement 1.2) and presents a simple command
prompt supporting:

    put <local_filename>     upload a file to the server
    get <remote_filename>    download a file from the server
    list                     list the files available on the server
    quit                     disconnect and exit

An informative status line is printed for every action, including transfer
completion and total bytes transferred.

Local-file collision policy for `get` (Requirement 1.2): AUTO-RENAME. If the
target name already exists locally, the download is saved as name_1.ext,
name_2.ext, ... (first free), so an existing file is never overwritten.

Usage:
    python3 FTPClient.py <server_ip> <server_port>
"""

import os
import socket
import sys

# Upper bound for a single recv() call. recv() may return fewer bytes; the
# helpers below loop until they have what the protocol needs.
RECV_CHUNK = 4096


# --------------------------------------------------------------------------- #
# Stream framing helpers - byte-for-byte identical to the server's copies so
# both sides frame messages the same way (Requirement 1.3).
# --------------------------------------------------------------------------- #
def send_line(conn, text):
    """Sends one ASCII command line, appending the '\\n' terminator."""
    conn.sendall((text + "\n").encode("ascii"))


def recv_line(conn, buffer):
    """Reads one '\\n'-terminated line.

    Returns:
        (line, leftover) - `line` is the decoded text without the trailing
        '\\n'; `leftover` holds any bytes received after the newline.

    Raises:
        ConnectionError: The peer closed before a full line arrived.
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

    Returns:
        (payload, leftover) - `payload` is exactly num_bytes long.

    Raises:
        ConnectionError: The peer disconnected before num_bytes arrived.
    """
    payload = buffer[:num_bytes]
    buffer = buffer[num_bytes:]
    while len(payload) < num_bytes:
        data = conn.recv(min(RECV_CHUNK, num_bytes - len(payload)))
        if not data:
            raise ConnectionError("connection closed mid-transfer")
        payload += data
    return payload, buffer


def unique_local_path(name):
    """Returns `name` if free, else name_1.ext, name_2.ext, ... (first free).

    Implements the auto-rename collision policy for `get` (Requirement 1.2).
    """
    if not os.path.exists(name):
        return name
    stem, ext = os.path.splitext(name)
    i = 1
    while os.path.exists(f"{stem}_{i}{ext}"):
        i += 1
    return f"{stem}_{i}{ext}"


# --------------------------------------------------------------------------- #
# Command implementations. Each takes and returns `buffer` so bytes received
# past one response survive to the next command.
# --------------------------------------------------------------------------- #
def do_list(sock, buffer):
    """Sends LIST and prints the file table returned by the server."""
    send_line(sock, "LIST")
    reply, buffer = recv_line(sock, buffer)

    parts = reply.split(" ", 1)
    if parts[0] != "OK":
        print(f"list failed: {reply}")
        return buffer

    count = int(parts[1])
    print(f"{count} file(s) on server:")
    for _ in range(count):
        entry, buffer = recv_line(sock, buffer)
        print(f"  {entry}")
    return buffer


def do_put(sock, local_path, buffer):
    """Reads a local file and uploads it with PUT <name> <size> + bytes."""
    if not os.path.isfile(local_path):
        print(f"put: local file not found: {local_path}")
        return buffer

    try:
        with open(local_path, "rb") as f:
            data = f.read()
    except OSError as err:
        print(f"put: cannot read {local_path}: {err.strerror}")
        return buffer

    # The server stores by base name only, so send just that.
    remote_name = os.path.basename(local_path)
    filesize = len(data)

    # Command line then payload, on the same connection, no delimiter.
    send_line(sock, f"PUT {remote_name} {filesize}")
    sock.sendall(data)
    print(f"Uploading {remote_name} ({filesize} bytes)...")

    reply, buffer = recv_line(sock, buffer)
    parts = reply.split(" ", 1)
    if parts[0] == "OK":
        print(f"Upload complete: {remote_name}, {filesize} bytes transferred.")
    else:
        # Requirement 1.4: print the server's ERR reason without crashing.
        print(f"Upload failed: {reply}")
    return buffer


def do_get(sock, remote_name, buffer):
    """Sends GET, receives the file, writes it locally (auto-renaming)."""
    send_line(sock, f"GET {remote_name}")
    reply, buffer = recv_line(sock, buffer)

    parts = reply.split(" ", 1)
    if parts[0] != "OK":
        # Requirement 1.4: e.g. "ERR file not found" - print, do not crash.
        print(f"get failed: {reply}")
        return buffer

    filesize = int(parts[1])
    print(f"Downloading {remote_name} ({filesize} bytes)...")
    data, buffer = recv_exact(sock, filesize, buffer)

    local_path = unique_local_path(os.path.basename(remote_name))
    try:
        with open(local_path, "wb") as f:
            f.write(data)
    except OSError as err:
        print(f"get: cannot write {local_path}: {err.strerror}")
        return buffer

    if local_path != os.path.basename(remote_name):
        print(f"(local file existed; saved as {local_path})")
    print(f"Download complete: {local_path}, {len(data)} bytes transferred.")
    return buffer


def command_loop(sock, buffer):
    """Reads user commands from the prompt and dispatches them."""
    while True:
        try:
            raw = input("mini-ftp> ").strip()
        except EOFError:                 # piped input exhausted / Ctrl+D
            raw = "quit"

        if not raw:
            continue

        parts = raw.split(" ", 1)        # verb + (rest as one argument)
        verb = parts[0].lower()
        arg = parts[1].strip() if len(parts) == 2 else ""

        if verb == "quit":
            send_line(sock, "QUIT")      # server just closes; no response
            break

        try:
            if verb == "list":
                buffer = do_list(sock, buffer)
            elif verb == "put":
                if not arg:
                    print("usage: put <local_filename>")
                    continue
                buffer = do_put(sock, arg, buffer)
            elif verb == "get":
                if not arg:
                    print("usage: get <remote_filename>")
                    continue
                buffer = do_get(sock, arg, buffer)
            else:
                print(f"unknown command: {verb!r} "
                      f"(try: put, get, list, quit)")
        except ConnectionError as err:
            print(f"Lost connection to server: {err}")
            break

    return buffer


def main():
    """Parses server_ip / server_port, connects, and runs the prompt."""
    if len(sys.argv) != 3:
        print("Usage: python3 FTPClient.py <server_ip> <server_port>")
        sys.exit(1)

    server_ip = sys.argv[1]
    try:
        server_port = int(sys.argv[2])
    except ValueError:
        print("Port must be an integer.")
        sys.exit(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((server_ip, server_port))
    except OSError as err:
        print(f"Could not connect to {server_ip}:{server_port} - {err}")
        sys.exit(1)

    print(f"Connected to {server_ip}:{server_port}. "
          f"Commands: put <file> | get <file> | list | quit")

    try:
        command_loop(sock, b"")
    finally:
        sock.close()
        print("Disconnected.")


if __name__ == "__main__":
    main()
