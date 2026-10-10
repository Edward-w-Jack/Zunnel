# Source files

This page lists what each file in the repository handles. [architecture.md](architecture.md)
explains how the pieces fit together.

## Repository root

| File | Handles |
|---|---|
| `build.zig` | The build graph: the `common`, server and agent modules; lwIP and mbedTLS as static libraries; the agent's baked-config build options (`-Dagent-*`); the `test`, `fuzz`, `server` and `agent` steps. |
| `build.zig.zon` | Package manifest. Pins the lwIP 2.2.1 and mbedTLS 3.6.7 source tarballs. |
| `README.md` | User guide: building, usage, privileges, reliability, roadmap. |
| `tools/patch.zig` | Build-time patcher for lwIP sources. Applies find/replace pairs and fails the build unless each pattern matches exactly once. |

## `src/common/`: shared by both programs

| File | Handles | Look at |
|---|---|---|
| `common.zig` | Module root: re-exports the files below and defines `version`. | |
| `proto.zig` | Frame header and frame types, wire constants (port, heartbeat, payload limit, flow-control window, local-address range, agent id bit), and payload codecs. | `FrameType`, `ConnectRequest`/`Endpoint`, `IcmpEcho`, `Accepted`, `FailReason` |
| `noise.zig` | The Noise `NKpsk0_25519_ChaChaPoly_BLAKE2s` handshake and transport ciphers, and deriving the PSK from the shared secret. | `Initiator`, `Responder`, `CipherState`, `pskFromSecret` |
| `link.zig` | The encrypted link: client and server handshakes, the record layer (encryption, padding, batching), the writer thread, heartbeats and dead-link detection, and reading frames. | `Link`, `clientHandshake`, `serverHandshake`, `Link.send`, `Link.recvFrame`, `testPair` |
| `stream.zig` | A byte-stream interface, so the link runs over raw TCP or TLS unchanged. | `Stream`, `TcpStream` |
| `sock.zig` | Socket helpers that behave the same on POSIX and Windows: uniform error sets, timeouts, non-blocking connect and send, listening sockets, UDP helpers. | `recv`, `send`, `sendAll`, `connect`, `tcpConnect`, `listenTcp`, `peekByte` |
| `reactor.zig` | Readiness reactor over `poll`/`WSAPoll` for the relay's I/O thread. Polls only sockets someone is waiting on; wakeups are coalesced. | `Reactor`, `Interest`, `Event` |
| `relay.zig` | Moves bytes between OS sockets and the link: dials, accepted connections, credit-based flow control, backpressure, flow lifecycle. One I/O thread per link. | `Table`, `Flow`, `Table.dial`, `Table.dispatch`, `adoptTcp`, `adoptUdp` |
| `keys.zig` | Base64 key encoding, and the server key file (private key plus shared secret), created on first run. | `encode`, `decode`, `loadOrCreate` |
| `clock.zig` | Monotonic milliseconds for every timeout. | `monotonicMs` |
| `logfmt.zig` | UTC timestamps and log-line formatting shared by both programs. | `timestamp`, `line` |

## `src/server/`: `zunnel-server`

| File | Handles | Look at |
|---|---|---|
| `main.zig` | Command-line options, startup (key file, TLS, server), clean shutdown, and the operator console: commands, tab completion, history, `save` and `-config`. | `main`, `Console.exec`, `Console.complete` |
| `server.zig` | Accepting agents: handshake limits, telling TLS from raw TCP, sessions (hello parsing, re-attaching bindings, restarting listeners), routing frames to tunnels or the relay, listener and relay bookkeeping, printing `ifconfig` answers. | `Server`, `Session`, `Listener`, `Binding`, `Server.sessionMain`, `Server.dispatch` |
| `tunnel.zig` | One TUN interface routed through one session. Packet input: TCP SYNs held until the agent's dial finishes, the dial queue, UDP flows, ICMP echo. Also lwIP callbacks, the TCP relay with credit, failure answers (RST, ICMP, silence), stale-flow sweeps, routes, flow listing. | `Tunnel`, `Tunnel.onPacket`, `handleFrameLocked`, `flushToAgent`, `flushToClient` |
| `netstack.zig` | The single shared lwIP instance: the global lock, the timer thread (lwIP timers, per-tunnel sweeps), and the C hooks lwIP calls (`sys_now`, random numbers, asserts, the route-source hook). | `lock`, `start`, `timerLoop` |
| `lwip.zig` | `@cImport` of the lwIP headers the server uses, and lwIP error constants. | |
| `packet.zig` | IPv4, TCP and UDP parsing. Building UDP datagrams, ICMP echo replies, ICMP unreachable messages and TCP RSTs. Checksums. Splitting oversized packets into fragments. | `parseIp4`, `parseIp4Header`, `buildUdp4`, `buildRst4`, `fragmentIp4` |
| `reassemble.zig` | IPv4 fragment reassembly for packets read from the TUN. Bounded to 64 datagrams at once, 32 ranges each, 30 s timeout. | `Table.offer`, `Table.sweep` |
| `tun.zig` | Platform TUN interface (chooses the backend per OS), MTU, tunnel addresses (`198.18.0.N`), CIDR parsing, and running helper commands. | `Tun`, `Cidr`, `runCommand` |
| `tun_linux.zig` | Linux TUN backend: `/dev/net/tun`, interface setup and routes via `ip`. | `Tun` |
| `tun_windows.zig` | Windows TUN backend on Wintun (loads `wintun.dll`). Adapter and ring setup; address, MTU, routes and the per-interface ICMP firewall rule via `netsh`. | `Tun` |
| `tls.zig` | TLS 1.3 server on mbedTLS: generates a self-signed certificate on first run, does socket I/O through `sock`, and exposes each accepted session as a `Stream`. | `Server.init`, `Server.accept` |
| `privileges.zig` | Startup checks: Administrator rights and `wintun.dll` on Windows; root, or a pre-created TUN, on Linux. | `check` |
| `ui.zig` | Operator output: the log function, `-v`/`-q` levels, the `-log` file, and events printed from other threads without disturbing the line being typed. | `logFn`, `event`, `out`, `showLine` |
| `lineedit.zig` | Console line editor: cursor movement, editing keys, history, completion actions. `Editor` is pure (bytes in, actions out); `Terminal` switches raw mode. | `Editor`, `Terminal` |

## `src/lwip/`: lwIP configuration

| File | Handles |
|---|---|
| `lwipopts.h` | lwIP build options: `NO_SYS`, TCP only, malloc-backed memory, 256 KiB windows with window scaling, one netif per tunnel, the route-source hook. |
| `arch/cc.h` | lwIP port header: byte order, and asserts and random numbers routed to the Zig functions exported by `netstack.zig`. |

## `src/agent/`: `zunnel-agent`

| File | Handles | Look at |
|---|---|---|
| `main.zig` | Command-line parsing, plus the environment and baked-config layers. Also handles the Windows windowed and service build modes, then runs the agent. | `main`, `argLayer`, `envLayer`, `bakedLayer` |
| `agent.zig` | The agent core: connecting (TCP, then TLS or raw, then Noise), the reconnect loop with backoff, `Session` (frame dispatch, listeners, ICMP workers, `ifconfig` answers), the stop and expiry watchdog. Tests run against a minimal fake server. | `run`, `runSession`, `Session.dispatch` |
| `config.zig` | Resolves settings from layers (flags, then environment, then baked), and parses `-connect` and `-expire`. | `Config`, `Layer`, `resolve` |
| `identity.zig` | Stable agent identity: a BLAKE2s hash of the OS machine ID and the user, without writing anything to disk. | `derive`, `machineId` |
| `listener.zig` | Listeners opened at the server's request. TCP: accepted connections are handed to the relay and announced with `accepted`. UDP: one association per peer address. | `Listener.start`, `tcpLoop`, `udpLoop` |
| `icmp.zig` | ICMP echo without privileges: `IcmpSendEcho` on Windows; ICMP datagram sockets elsewhere, falling back to the system `ping`. | `echo` |
| `netinfo.zig` | Lists interfaces, addresses and the default gateway for `ifconfig`, without privileges, on Windows, Linux and macOS. | `write` |
| `tls.zig` | TLS client on `std.crypto.tls.Client`, exposed as a `Stream`. Certificate checks are optional (`-tls-verify`, `-ca`). | `connect` |
| `service_windows.zig` | Windows service mode for `-Dagent-service` builds: `install-service`, `uninstall-service`, and running under the Service Control Manager. | `install`, `uninstall`, `tryDispatch` |
