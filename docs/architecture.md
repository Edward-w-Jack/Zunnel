# Architecture

This document describes how zunnel is put together:

- the two programs and the link between them,
- the path a packet takes through the server,
- the relay that moves bytes between sockets and the link,
- how threads and locks are organised.

[protocol.md](protocol.md) specifies the wire format, and [files.md](files.md) says what each
source file handles.

## Components

zunnel is two executables built from three Zig modules:

| Module | Root | Built into | Role |
|---|---|---|---|
| `common` | `src/common/common.zig` | both | link (Noise + records), wire protocol, sockets, reactor, relay, keys, clocks |
| server | `src/server/main.zig` | `zunnel-server` | TUN interfaces, lwIP netstack, agent sessions, operator console |
| agent | `src/agent/main.zig` | `zunnel-agent` | connects to the server and opens sockets on its behalf |

The server links two C libraries, both fetched by the Zig package manager: lwIP, which terminates
TCP, and mbedTLS, which provides the TLS server. The agent links neither and uses only Zig's
standard library, so it builds as a single static binary for any target Zig supports.

```
                      zunnel-server (elevated)                   zunnel-agent (unprivileged)
               ┌───────────────────────────────────┐          ┌───────────────────────────────┐
  your tools ─►│ TUN ─► Tunnel ─► Session ─► Link  │── TCP ──►│ Link ─► Session ─► sockets ─► │─► target
               │        (lwIP for TCP)             │ TLS 1.3  │   (listeners, ICMP, ifconfig) │   network
               │ Console ─► Server                 │  Noise   │                               │
               └───────────────────────────────────┘          └───────────────────────────────┘
```

The agent opens the connection; everything after the handshake flows both ways over it.

## The link

Each agent has exactly one link: a single TCP connection that the agent opens to the server
(default port 11601). Every flow, ping, listener and control message between that agent and the
server is multiplexed over it.

The link has three layers:

1. **Transport.** By default it is TLS 1.3: the server's side runs on mbedTLS with a self-signed
   certificate it generates on first run, and the agent uses `std.crypto.tls.Client`. The server
   peeks at the first byte: `0x16` (a TLS handshake record) means TLS, anything else means raw
   TCP. Both are accepted unless the server runs with `-no-tls`, which turns TLS off.
   `stream.Stream` hides the difference from the layers above.
2. **Noise.** `Noise_NKpsk0_25519_ChaChaPoly_BLAKE2s`. The agent knows the server's static public
   key in advance (`-pubkey`), and the shared secret becomes the PSK. Authentication therefore
   comes from Noise, not from TLS certificates: an agent with the wrong key or secret fails here.
3. **Records and frames.** After the handshake, each record is encrypted and carries one or more
   frames (`type | flags | id | len | payload`). A writer thread per link packs everything
   queued into as few records as possible.

`Link.send` never blocks: it appends the frame to a queue and signals the writer thread. Frames
marked droppable (UDP data) are discarded once more than 8 MiB is queued; everything else is
queued unconditionally and bounded by flow control.

## Server

### Threads

| Thread | Code | Job |
|---|---|---|
| main | `main.zig` `Console.run` | reads console commands and runs them |
| accept | `server.zig` `Server.acceptLoop` | accepts agent connections, enforces handshake limits |
| session, one per agent | `server.zig` `Server.sessionMain` | handshake, then reads frames and dispatches them |
| link writer, one per agent | `link.zig` `Link.writerLoop` | encrypts and sends queued frames, sends heartbeats |
| relay I/O, one per agent | `relay.zig` `ioMain` | server-side sockets for flows from agent listeners |
| TUN reader, one per interface | `tunnel.zig` `Tunnel.readerLoop` | reads packets from the TUN device into the netstack |
| netstack timer | `netstack.zig` `timerLoop` | lwIP timers every 50 ms, flow sweeps every second |
| shutdown watcher (POSIX) | `main.zig` `shutdownWatcher` | turns SIGINT/SIGTERM into a clean shutdown |

On Windows, the console control handler runs the same shutdown on its own thread.

### Locks

| Lock | Guards |
|---|---|
| `Server.mutex` | sessions, tunnels, listeners, bindings, relay port map, handshake counters |
| `netstack.lock` | every lwIP call and all `Tunnel` flow state |
| `Link.mutex` | one link's send queue |
| `relay.Table.mutex` | one link's relay flows |

Locks are always taken in the order `Server.mutex` → `netstack.lock` → `Link.mutex`. A relay
table's mutex may be held while queueing a frame on its link. lwIP callbacks run only inside lwIP
calls made while holding `netstack.lock`, so they can touch flow state directly.

### Packet path

Packets for routed networks arrive on a TUN device. `Tunnel.readerLoop` takes `netstack.lock`
for each one and calls `onPacket`:

1. **Reassembly.** IPv4 fragments go to `reassemble.Table`; only complete datagrams continue.
2. **TCP SYN** for a new 4-tuple (`newTcpFlow`):
   - A `Flow` is created, the SYN is kept, and a `connect` frame asks the agent to dial the
     destination with the configured dial timeout. If the interface already has `-max-dials`
     dials in flight, the flow waits in a queue instead.
   - On `connect_ok` the stored SYN is fed into lwIP. lwIP's wildcard listener completes the
     handshake with the client, and `onAccept` attaches the new pcb to the flow.
   - On `connect_fail` the client gets the answer the real network would have given: a RST for
     a refused connection, ICMP unreachable for unreachable or prohibited destinations, and
     nothing for a timeout. The verdict is cached for 10 s, so retransmitted SYNs get the same
     answer without another dial.
3. **Other TCP segments** for known flows go to lwIP. Segments for connections that never
   existed are dropped silently, rather than answered with a RST.
4. **UDP** bypasses lwIP. The first datagram of a 4-tuple opens a flow (`connect` with transport
   UDP), and each datagram travels as one `data` frame. Replies are rebuilt into IP packets
   (`packet.buildUdp4`) and fragmented if they exceed the 1500-byte MTU. Flows end after 120 s
   idle.
5. **ICMP echo** becomes an `icmp_echo` request to the agent. The server writes an echo reply
   only if the agent's ping succeeded. Destinations in `-localhost-net` are answered locally.

### TCP relay inside the server

Once a flow is open, the server relays bytes between the lwIP pcb and the agent:

- **Client → agent.** `onRecv` copies lwIP data into `from_client`. `flushToAgent` sends it as
  `data` frames while the agent has granted credit. It calls `tcp_recved` only for bytes
  actually sent, so lwIP's receive window, and with it the client, slows down when the agent
  does.
- **Agent → client.** `data` frames land in `to_client`, and `flushToClient` writes as much as
  lwIP's send buffer accepts. Credit goes back to the agent as `window` frames, in batches of
  32 KiB.
- **Close.** Each direction closes with a `fin` frame (half-close). The flow ends when both
  directions have finished, or at once on a reset from either side.

### lwIP integration

One lwIP instance serves every tunnel. It runs in `NO_SYS` mode, and `netstack.lock` serialises
all access to it. Each tunnel adds one netif (address `198.18.0.N`) and one wildcard TCP
listener bound to that netif.

Three patches, applied at build time by `tools/patch.zig`, let lwIP terminate connections to
any destination:

- accept packets for every destination address,
- let the single listener match every port,
- keep the port the client actually dialed on accepted pcbs.

Two hooks complete the integration. `LWIP_HOOK_IP4_ROUTE_SRC` sends unbound output (such as a
RST) back out of the netif the input arrived on. `sys_now` uses the monotonic clock. lwIP handles
only TCP; UDP, ICMP, fragmentation and reassembly are done in Zig (`lwipopts.h`).

### Sessions, identities and bindings

A `Session` exists for each connected agent. The agent's hello (sent inside Noise message 1)
carries `key=value` lines: version, id, hostname, user, OS, architecture, PID, and an optional
expiry.

The `id` is the agent's identity: a hash of the host's machine ID and the user, so it survives
reconnects (`identity.zig`). State that should outlive a connection is keyed by identity, not by
session:

- **Bindings** (`bind`, `start`) re-attach an interface to its agent whenever that agent
  reconnects.
- **Listeners** are restarted on the agent when it reconnects.

When a session ends, its tunnels are detached, which aborts their flows, and its listeners are
marked inactive until the agent returns.

### Listeners and relays

`listener add` asks an agent to listen on a TCP or UDP port:

1. Each accepted connection, or each new UDP peer, becomes an agent-side flow. Its id has
   bit 31 set, and the agent announces it with an `accepted` frame.
2. The server's relay table dials the listener's target from the operator machine and answers
   `connect_ok` or `connect_fail`.
3. From then on the flow behaves like any other.

`relay <agent>` is a listener whose target is the server's own listening port. A deeper agent can
then connect to the server through an existing agent. Its connection arrives on loopback, and
`Server.relay_ports` maps the local port to the upstream session, so the new session is shown as
"via agent #N". Each hop is a complete, separate link with its own handshake.

### Console

`main.zig` contains the `Console`: command parsing and execution, tab completion, history in
`~/.zunnel_history`, `save` (writes the current setup as commands), and `-config` (replays such a
file at startup). `lineedit.zig` provides raw-mode line editing. `ui.zig` prints events and log
lines from other threads without breaking the line being typed, and mirrors them to `-log`.

## Agent

### Threads

| Thread | Code | Job |
|---|---|---|
| main | `agent.zig` `run`, `Session.run` | connects, reads and dispatches frames, reconnects with backoff |
| link writer | `link.zig` `Link.writerLoop` | sends queued frames and heartbeats |
| watchdog | `agent.zig` `Session.watch` | ends the session on stop or expiry |
| relay I/O | `relay.zig` `ioMain` | every socket the agent dials, and TCP connections its listeners accept |
| listener, one per listener | `listener.zig` | accepts TCP connections, receives UDP datagrams |
| ICMP worker, short-lived | `agent.zig` `icmpWorker` | one ping each, at most 32 at a time |

### Frame handling

`Session.dispatch` routes incoming frames:

| Frame | Handled by |
|---|---|
| `connect` | `relay.Table.dial`, a non-blocking connect on the I/O thread (at most 512 in flight) |
| `data`, `window`, `fin`, `reset`, `connect_ok`, `connect_fail` | `relay.Table.dispatch` |
| `icmp_echo` | an ICMP worker thread (`icmp.zig`) |
| `listener_add`, `listener_del` | `listener.zig` |
| `info_request` | `netinfo.write`, answered with `info_reply` |
| `kill` | ends the session and stops the agent for good |

The agent dials any destination in `240.0.0.0/4` as `127.0.0.1`. The server also rewrites
destinations in its own `-localhost-net` to `127.0.0.1` before sending `connect`. Its default
`-localhost-net` is that same range.

### Configuration and lifecycle

Settings resolve from command-line flags, then `ZUNNEL_*` environment variables, then values baked
in at build time (`config.zig`, `-Dagent-*` build options). A baked agent therefore runs with no
arguments.

With `-retry`, the agent reconnects after a failure. The wait starts at 1 s and doubles up to
30 s; it resets after a session that connected successfully. Agents with a baked
`-Dagent-connect` retry by default. `-expire` stops the agent for good at a deadline.

Two Windows build options exist:

- `-Dagent-windowed` builds the agent for the GUI subsystem.
- `-Dagent-service` adds `install-service` and `uninstall-service` and lets the Service Control
  Manager start the agent (`service_windows.zig`).

## The relay

`common/relay.zig` moves bytes between OS sockets and the link, and both programs use it:

- **On the agent**, a `Table` owns every socket: flows the server asked it to dial, and flows its
  listeners accepted.
- **On the server**, each session's `Table` owns the sockets it dials for those listener flows.

Each `Table` runs on a single I/O thread driven by `reactor.zig`. Public methods (`dial`,
`dispatch`, `adoptTcp`, `adoptUdp`) are called from other threads. They take `Table.mutex`, update
state, and wake the I/O thread.

Each `Flow` in a table moves through these states:

| State | Meaning |
|---|---|
| `connecting` | non-blocking connect in progress (dialed flows) |
| `waiting` | accepted by a listener, waiting for the server's `connect_ok` |
| `open` | relaying |
| finished | both directions closed (`rx_eof` and `tx_closed`), or aborted by a reset or error |

A finished flow is closed and freed on the I/O thread's next pass, whether or not it still has
data buffered.

Flow control and buffering work as follows:

- A TCP flow reads its socket only while the peer has granted credit. It returns credit with
  `window` frames after writing peer data to the socket.
- When the socket's send buffer is full, the rest stays buffered and the flow waits until the
  socket is writable again. The withheld credit slows the sender down.
- A peer that sends more than twice the window without waiting for credit gets a reset.

The reactor polls only sockets that some flow is waiting on. It reports a hang-up or error as
readable or writable, so the next `recv` or `send` sees it and the flow ends. `wake()` sends one
datagram to a loopback UDP socket, and further wakes are skipped until the I/O thread has drained
it.

## Flow control

Every TCP flow has a credit window of 256 KiB in each direction. The receiving side returns credit
as it delivers bytes onward, so a slow consumer anywhere in the chain eventually stops the
producer. On the server that consumer is lwIP's send buffer toward the client; on the agent it is
the target socket. The link itself never has to buffer more than the open windows.

UDP has no credit. Datagrams are dropped when the link's queue is congested, as a real network
would drop them. See [protocol.md](protocol.md#flow-control) for the exact rules.

## Limits and timers

| What | Value | Where |
|---|---|---|
| Heartbeat ping / link declared dead | every 10 s / after 30 s without a record | `proto.zig`, `link.zig` |
| Handshake timeout | 10 s | `link.zig` |
| Handshakes in progress | 64 total, 8 per source address | `server.zig` |
| Server TCP dials in flight per interface | 256 (`-max-dials`); extra SYNs queue, up to 8192 | `tunnel.zig` |
| Agent dials in flight | 512 | `relay.zig` |
| Default dial timeout | 3 s (`-dial-timeout`) | `proto.zig` |
| TCP flow-control window | 256 KiB per flow and direction | `proto.zig` |
| UDP flow idle timeout | 120 s | `tunnel.zig`, `relay.zig` |
| Cached dial failures | 10 s | `tunnel.zig` |
| Fragment reassembly | 64 datagrams at once, 30 s each | `reassemble.zig` |
| Largest frame payload | 65,507 bytes (the IPv4 UDP maximum) | `proto.zig` |
| ICMP echoes in flight | 256 per interface (server), 32 (agent) | `tunnel.zig`, `agent.zig` |

All timeouts use `clock.monotonicMs`, so changes to the system time don't affect them. Only log
timestamps and `-expire` use the wall clock.

## Build

`build.zig` defines these pieces:

- The `common`, server and agent modules.
- lwIP as a static library. The unmodified core files are compiled as-is, and the three patched
  files are produced by running `tools/patch.zig` at build time. The patcher fails the build if a
  pattern doesn't match exactly once, so an lwIP upgrade can't silently drop a patch.
- mbedTLS 3.6 as a static library, linked into the server only.
- An options module with the agent's baked settings (`-Dagent-connect`, `-Dagent-pubkey`, …).
- Steps: `test`, `fuzz`, and `server` / `agent` (build and run).

`build.zig.zon` pins the lwIP and mbedTLS source tarballs. `-Drelease` selects `ReleaseSafe`, which
keeps bounds and overflow checks, because both programs parse untrusted network input.

## Tests

`zig build test` runs three test binaries:

- **common:** Noise handshake, link records and handshake rejection, reactor behaviour, relay
  data paths, socket helpers, and protocol codecs. The relay tests run a real `Table` against a
  loopback link pair and loopback targets, covering both close orders, resets with buffered data,
  backpressure, UDP unreachable, and dial-slot accounting.
- **server:** packet building and parsing, fragmentation and reassembly, flow timeouts, CIDR
  handling, the line editor, and the TLS server.
- **agent:** configuration layering, identity, interface listing, and a session against a
  minimal fake server.

`zig build fuzz --fuzz` fuzzes the parsers that see untrusted input (Linux only). Without
`--fuzz` it runs the fuzz corpus once.
