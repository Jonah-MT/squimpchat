# squimpchat

A QUIC-based encrypted chat application written in C. Messages are end-to-end encrypted using X25519 key exchange and AES-256-GCM. The transport layer is [MsQuic](https://github.com/microsoft/msquic) v2.5.8.

---

## Dependencies

| Dependency | Purpose |
|---|---|
| MsQuic v2.5.8 | QUIC transport (bundled in `lib/`) |
| OpenSSL (libcrypto) | X25519, AES-256-GCM, SHA-256 |
| libreadline | Client terminal UI |
| gcc, make | Build |

The MsQuic library is bundled as a prebuilt binary (`lib/libmsquic.so.2`). Its runtime dependencies — `libcrypto.so.3` and `libnuma` — must be present on the system. On Ubuntu/Debian:

```sh
sudo apt install libssl-dev libnuma-dev
```

---

## Building

```sh
make
```

To build with debug packet logging:

```sh
make DEBUG=1
```

***I have tested the build on tux and no extra installation of dependencies should be required there***

Binaries are placed in `bin/`. TLS certificates are auto-generated in `certs/` if they don't exist.

---

## Setup

### Add users

Before starting the server, populate `data/users.txt` using the included utility:

```sh
data/sqmp-add-user <username> <password> [path-to-users-file]
```

If the third argument is omitted, it defaults to `users.txt` in the current directory. Passwords are stored as SHA-256 hashes.

**For convenience, the following users are already added to users.txt**
| Username | Password |
|---|---|
| jonah | jonahpass |
| prof  | profpass  |
| squimpy | squimpypass |
| mario | mariopass |

---

## Running

### Server

```sh
./bin/server
```

The server listens on port **4433** and reads users from `data/users.txt`.

### Client

```sh
./bin/client <server ip/hostname>
```

After connecting, you'll be prompted for a username and password. Typing is echo-suppressed for the password.

Once logged in, send a message with:

```
> <recipient_username> <message text>
```

For example, to send the message "hello" to a user called "jonah", enter:
```
> jonah hello
```

Type `quit`, `exit`, or press Ctrl+C to disconnect.

***Currently, the project only supports sending messages between connected users. Trying to send a message to a user who is not connected will result in an error***

---

#### Short Demo:
![demo](demo.gif)

---

## Project Structure

```
src/
  server/server.c           server logic and event handlers
  client/client.c           client logic, encryption, and terminal UI
  shared/sqmp.c             application protocol message handlers
  shared/msquic_wrapper.c   thin abstraction layer over the MsQuic API
include/
  sqmp.h                    protocol packet structs, message types, session state
  msquic_wrapper.h          QUIC context/connection/stream API
  server.h / client.h       compile-time config (port, ALPN, file paths)
  debug.h                   dbg_printf macro (active only in DEBUG builds)
data/
  sqmp_add_user.c           user management utility
  users.txt                 user database (username:sha256hex)
lib/
  libmsquic.so.2            bundled MsQuic shared library
```

---

## How It Works

### Transport

The application runs over QUIC using MsQuic. The server uses a self-signed TLS certificate; the client skips certificate validation. ALPN is `squimp`. Each client connection opens a single bidirectional stream for all traffic.

`msquic_wrapper.c` wraps the MsQuic callback-based API into a simpler interface. Callers register callbacks (`on_connected`, `on_stream_recv`, `on_disconnected`, etc.) via a config struct.

### Application Protocol

Each packet has a 12-byte fixed header (`sqmp_pkt_t`) containing a version, message type, and session ID, followed by a variable-length message body. Message handling is done by `sqmp.c` (shared server/client logic).

The session goes through these states in order:

```
HELLO  →  AUTH  →  CONN_ESTABLISHED  →  CLOSING → CLOSED
```

1. **Handshake** — client sends `HELLO` with its supported protocol versions (version 1 always). server responds with `HELLO_ACK` selecting version 1 and assigning a session ID.
2. **Auth** — client sends `AUTH_REQ` with a username, SHA-256 password hash, and its X25519 public key. The server verifies credentials against `users.txt` on a dedicated auth thread and responds with `AUTH_RESP`.
3. **Chat** — once authenticated, clients can send messages. Before each message, the sender requests the recipient's public key from the server (`KEY_REQ`/`KEY_RESP`). The server maintains a registry of logged-in users and their public keys.
4. **Disconnect** — either side can send `BYE`; the other echoes it back before closing.

### End-to-End Encryption

Messages are encrypted client-to-client; the server only sees ciphertext.

For each message:

1. The sender generates a fresh ephemeral X25519 keypair.
2. X25519 Diffie-Hellman is performed between the ephemeral private key and the recipient's registered public key to produce a shared secret.
3. SHA-256 of the shared secret is used as a 256-bit AES-GCM key.
4. The message is encrypted with AES-256-GCM using a random 12-byte nonce. A 16-byte authentication tag is appended to the ciphertext.
5. The ephemeral public key, nonce, and ciphertext are bundled into a `CHAT_SEND` packet and forwarded by the server to the recipient as `CHAT_DELIVER`.
6. The recipient performs X25519 with their private key and the ephemeral public key to derive the same AES key, then decrypts.

### Server Architecture

The server is single-threaded from the application's perspective. The main loop blocks on `sqmp_auth_queue_dequeue()`, processing one login at a time. MsQuic callbacks (stream receive, connect, disconnect) fire on MsQuic's internal threads and communicate with the main thread via semaphores and a lock-protected queue.

### Client Terminal UI

The client uses readline with a persistent `> ` prompt. Incoming messages from other threads call `rl_clear_visible_line()` before printing and `rl_forced_update_display()` after, so arriving messages don't corrupt the input line. An `rl_event_hook` polls a `g_interrupted` flag every 100ms so Ctrl+C cleanly exits readline without relying on readline's built-in signal handling.
