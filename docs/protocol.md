# Link protocol (ZNL6)

This is the format spoken between an agent and the server over their single connection. The code
lives in `src/common/link.zig` (handshake and records), `src/common/noise.zig` (cryptography) and
`src/common/proto.zig` (frames and payloads). All integers are big-endian unless noted.

## Connection setup

1. The agent opens a TCP connection to the server (default port 11601).
2. **Transport.** The server waits up to 2 s for the first byte. If it is `0x16` (a TLS handshake
   record), the connection is TLS 1.3. Otherwise it is raw TCP. A server started with `-no-tls`
   only speaks raw TCP.
3. **Noise handshake** (`Noise_NKpsk0_25519_ChaChaPoly_BLAKE2s`), which must finish within 10 s:

   ```
   agent -> server : len u16 | message 1   (-> psk, e, es; payload = hello, at most 4096 bytes)
   server -> agent : len u16 | message 2   (<- e, ee; empty payload)
   ```

   - **Prologue.** `zunnel-znl6` is mixed into the handshake hash but never sent. A version
     mismatch therefore fails authentication exactly like a wrong key.
   - **PSK.** `BLAKE2s-256("zunnel-psk-v1:" || secret)`, or 32 zero bytes when the server runs
     with `-no-secret`.
   - **Keys.** The agent must know the server's static public key in advance (`-pubkey`).
   - **Failure.** At the Noise layer the server sends nothing until it has read a valid
     message 1. If message 1 fails to authenticate, it closes the connection.
4. Both sides switch to transport records.

## Hello

The payload of message 1 is plain text, one `key=value` per line:

| Key | Value |
|---|---|
| `version` | agent version (`common.version`) |
| `id` | agent identity: 16 hex characters derived from machine ID and user, or `-id` |
| `hostname`, `user` | host and account the agent runs as |
| `os`, `arch` | target OS and CPU architecture |
| `pid` | process ID |
| `expire` | optional: Unix time in milliseconds when the agent stops for good |

Unknown keys are ignored.

## Records

On the wire each record is:

```
len u16 | ciphertext[len]
```

The ciphertext is ChaCha20-Poly1305 with a 16-byte tag. Details:

- **Keys.** Each direction has its own key from the handshake.
- **Nonce.** A 64-bit counter, starting at 0, stored little-endian in bytes 4..12 of the 12-byte
  nonce.
- **Associated data.** None.

The decrypted plaintext is:

```
real_len u16 | frames[real_len] | padding
```

- **Padding.** Random bytes up to the next multiple of 512 bytes of plaintext (`2 + real_len`
  rounded up), capped at 65,519 bytes. Receivers ignore the padding.
- **Batching.** The sender's writer thread packs as many queued frames as fit into each record
  (at most 65,517 bytes of frames).
- **Frame boundaries.** A frame never spans two records.

## Frames

Each frame is an 8-byte header and a payload:

```
type u8 | flags u8 | id u32 | len u16 | payload[len]
```

- `flags` is always 0.
- `len` is at most 65,507 (the largest UDP datagram over IPv4).

`id` names a flow, ICMP request, listener or info request. The server allocates ids below
`0x80000000`, separately for each session. The agent allocates ids with bit 31 set, for
connections its listeners accept.

| Type | Value | Direction | Payload |
|---|---|---|---|
| `ping` | 1 | both | sender's timestamp (8 bytes); answered with `pong` |
| `pong` | 2 | both | the ping's payload, echoed |
| `connect` | 3 | server → agent | `ConnectRequest`: open a flow |
| `connect_ok` | 4 | answer to `connect` or `accepted` | empty |
| `connect_fail` | 5 | answer to `connect` or `accepted` | `FailReason` (1 byte) |
| `data` | 6 | both | TCP bytes, or exactly one UDP datagram |
| `window` | 7 | both | credit u32: bytes the sender may send |
| `fin` | 8 | both | empty: no more data in this direction (TCP half-close) |
| `reset` | 9 | both | empty: abort the flow in both directions |
| `icmp_echo` | 10 | server → agent | `IcmpEcho`: ping this address |
| `icmp_reply` | 11 | agent → server | ok u8, rtt_ms u16 |
| `listener_add` | 12 | server → agent | `Endpoint`: transport and bind address; id = listener id |
| `listener_ok` | 13 | agent → server | empty |
| `listener_fail` | 14 | agent → server | error text (at most 200 bytes) |
| `listener_del` | 15 | server → agent | empty |
| `accepted` | 16 | agent → server | listener id u32, then the peer as an `Endpoint`; id = new flow id |
| `icmp_unreachable` | 17 | agent → server | ICMP code u8 (3 = port unreachable); the UDP flow stays open |
| `kill` | 18 | server → agent | empty: stop for good, no reconnect |
| `info_request` | 19 | server → agent | empty; id = request id |
| `info_reply` | 20 | agent → server | interface list as text lines (see below) |

Receivers ignore frames of unknown type, and frames for ids they don't know.

### Payload encodings

**`ConnectRequest` / `Endpoint`** (used by `connect`, `listener_add` and `accepted`):

```
transport u8 | port u16 | addr_len u8 | addr[addr_len] | [timeout_ms u16]
```

- `transport` is 6 for TCP and 17 for UDP.
- `addr_len` is 4 (IPv4) or 16 (IPv6).
- `timeout_ms` is optional. The server sends it with TCP `connect` requests (its `-dial-timeout`);
  without it, the agent uses 3000 ms.

**`FailReason`:**

| Code | Name | The server answers the client with |
|---|---|---|
| 1 | `refused` | TCP RST |
| 2 | `unreachable_host` | ICMP host unreachable |
| 3 | `timeout` | nothing |
| 4 | `other` | TCP RST |
| 5 | `unreachable_net` | ICMP network unreachable |
| 6 | `prohibited` | ICMP administratively prohibited |

**`IcmpEcho`:** `addr[4] | timeout_ms u16`.

**`info_reply`** lines:

```
iface=<name> <addr>/<prefix> [<addr>/<prefix> ...]
gateway=<addr> <iface>
```

The reply is cut at a line boundary if it would exceed the maximum payload.

## Flows

**TCP flow opened by the server:**

1. The server sends `connect`. The agent answers `connect_ok` once its socket connects, or
   `connect_fail`.
2. Both sides exchange `data` and `window` frames.
3. Each direction ends with its own `fin`. The flow is over when both have been sent, or when
   either side sends `reset`.

**UDP flow opened by the server:**

1. The server sends `connect` with transport 17, and the agent answers `connect_ok` once it has a
   connected UDP socket.
2. Each `data` frame is one datagram. `icmp_unreachable` reports that the target answered with
   ICMP unreachable. UDP flows have no `fin`.
3. Either side forgets the flow after 120 s without traffic.

**Flow from an agent listener:**

1. The agent sends `accepted` with a new id (bit 31 set).
2. The server dials the listener's target and answers `connect_ok` or `connect_fail`.
3. From then on the flow follows the TCP or UDP rules above.

**Local addresses.** Destinations in `240.0.0.0/4` are dialed as the agent's own `127.0.0.1`. The
server rewrites addresses in its `-localhost-net` to `127.0.0.1` before sending `connect`.

## Flow control

Flow control applies to TCP flows, in each direction separately:

- **Starting credit.** Each sender starts with 256 KiB of credit.
- **Sending.** Every `data` byte uses up credit, and a sender with no credit sends nothing more.
- **Returning credit.** The receiver returns credit in `window` frames as it passes bytes on: to
  the target socket on the agent, to lwIP on the server. It returns credit in batches of at least
  32 KiB, or as soon as its buffer is empty.
- **Violations.** A receiver that ends up holding more than twice the window for one flow resets
  it.

UDP has no credit. A link whose send queue holds more than 8 MiB drops UDP `data` frames instead
of queueing them.

## Heartbeat

Each side sends a `ping` every 10 s, and the other side answers with a `pong`. Any record received
counts as a sign of life. A side that receives nothing for 30 s closes the link, and the agent
reconnects if it runs with `-retry`.

## Versioning

The digit in the prologue (`zunnel-znl6`, in `proto.zig`) is the wire version. Bump it whenever
the handshake, record format or frame encoding changes incompatibly. Mismatched agents and servers
then fail the handshake cleanly instead of misparsing each other.
