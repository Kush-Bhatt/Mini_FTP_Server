# Mini File Transfer Protocol (Mini-FTP)

ACN Programming Assignment 2 — a simplified file-transfer protocol implemented
twice: once over **TCP** (reliability handled by the transport) and once over
**UDP** (reliability built by hand with a stop-and-wait layer).

Each client can **upload** (`put`), **download** (`get`), and **list** the files
held by the server.

| Part | Transport | Reliability | Files |
|------|-----------|-------------|-------|
| 1 (required) | TCP | provided by the kernel | `FTPServer.py`, `FTPClient.py` |
| 2 (required) | UDP | stop-and-wait: timeouts, ACKs, retransmission | `UDPFTPServer.py`, `UDPFTPClient.py` |
| 3 (bonus)    | UDP + resume | resume an interrupted transfer | *not yet implemented* |

Requires **Python 3** only (standard library: `socket`, `struct`, `threading`,
`hashlib`). No third-party packages.

---

## Part 1 — TCP

```bash
# terminal 1 — server (port must be > 10000)
python3 FTPServer.py 12345

# terminal 2 — client
python3 FTPClient.py 127.0.0.1 12345
```

Client prompt:

```
mini-ftp> put report.pdf        # upload a local file
mini-ftp> get report.pdf        # download; auto-renamed to report_1.pdf if it exists
mini-ftp> list                  # list files on the server
mini-ftp> quit
```

**Behaviour**

- Server is concurrent — one thread per connection, so multiple clients
  transfer at the same time.
- All server files live under `server_storage/` (created on startup); paths are
  sandboxed to that directory.
- `SO_REUSEADDR` so the server restarts immediately during testing.
- `get` never overwrites a local file — it auto-renames to `name_1.ext`,
  `name_2.ext`, …

**Wire format** — one ASCII line ending in `\n`, then the raw payload with no
separator:

| Command | Client sends | Server replies |
|---------|--------------|----------------|
| Upload   | `PUT <name> <size>\n` + `<size>` bytes | `OK <size>\n` \| `ERR <reason>\n` |
| Download | `GET <name>\n` | `OK <size>\n` + `<size>` bytes \| `ERR <reason>\n` |
| List     | `LIST\n` | `OK <count>\n` + `<count>` × `<name> <size>\n` |
| Quit     | `QUIT\n` | (server closes the connection) |

---

## Part 2 — UDP with stop-and-wait reliability

```bash
# terminal 1 — server
python3 UDPFTPServer.py 13000

# terminal 2 — client
python3 UDPFTPClient.py 127.0.0.1 13000
```

Prompt is the same (`put` / `get` / `list` / `quit`).

**Protocol**

- **Control** — one ASCII `|`-separated datagram (`PUT|name|size|chunks`,
  `GET|name|0`, `LIST`, `DONE|<md5>`), resent every 0.5 s up to 5 times.
- **DATA** — 7-byte header `!IBH` = `(seq, is_last, data_len)` + up to 1000
  file bytes.
- **ACK** — 4 bytes `!I` = `seq`.
- **Stop-and-wait** — send one chunk, wait 0.5 s for its ACK, resend on
  timeout, abort a chunk after 10 consecutive timeouts.
- **Integrity** — after the last chunk the sender sends `DONE|<md5>`; the
  receiver compares it against the file it assembled and replies `VERIFIED`
  or `MISMATCH`.

**Simulating packet loss for development**

```bash
python3 UDPFTPServer.py 13000 --loss-rate 0.2
python3 UDPFTPClient.py 127.0.0.1 13000 --loss-rate 0.2
```

`--loss-rate` drops that fraction of outgoing datagrams at the application
layer. It defaults to `0.0` and **must stay 0.0 for graded runs** — real loss
is injected at the NIC with `tc netem`:

```bash
sudo tc qdisc add dev lo root netem loss 10%
#   ... run the transfer ...
sudo tc qdisc del dev lo root
```

**Known limitations** (to be discussed in the report)

- The UDP server handles one transfer at a time; concurrent clients are
  serialized. Each client is still identified by its `(IP, port)` so ACKs are
  routed correctly.
- `LIST` assumes its reply fits in a single datagram.

---

## Verifying a transfer

```bash
md5sum myfile.pdf                       # before
# ... put then get through Mini-FTP ...
md5sum myfile_1.pdf server_storage/myfile.pdf   # after — all three should match
```

Part 2 also prints `VERIFIED` on both sides automatically.

---

## Repository layout

```
FTPServer.py        FTPClient.py        # Part 1 (TCP)
UDPFTPServer.py     UDPFTPClient.py     # Part 2 (UDP)
server_storage/                         # created at runtime, git-ignored
```

Coding style follows PEP 8 and the Google Python style guide.
