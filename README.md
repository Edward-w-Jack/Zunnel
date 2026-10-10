# zunnel

A ligolo-style tunnelling tool written in Zig. An unprivileged **agent** on a remote host
connects back to the **proxy** on your machine; the proxy exposes a TUN interface so you can
reach the agent's networks with ordinary tools (nmap -sT, ssh, curl, smbclient, ...),
with no SOCKS and no proxychains.

```
 your tools ──► TUN (zunnel) ──► lwIP netstack ──► Noise link ──► agent ──► target network
                 proxy (root/admin)                             (no privileges)
```

## How it works

- **Proxy** (`zunnel-proxy`, Linux and Windows) reads raw IP packets from the TUN device.
  - **TCP** is terminated by [lwIP](https://savannah.nongnu.org/projects/lwip/). The proxy
    holds each client SYN until the agent's real `connect()` succeeds, then replays it into
    lwIP. A failed dial is answered with RST, so port scans report accurate open/closed results.
  - **UDP** is relayed per flow (DNS works) without going through lwIP.
  - **ICMP echo**: the agent pings the target (no privileges needed: `IcmpSendEcho` on
    Windows; unprivileged ICMP sockets or the `ping` binary elsewhere). The proxy answers
    only if the target replied, so `ping` and nmap host discovery work.
  - Several TUN interfaces can run at once, each routed through a different agent. They all
    share one lwIP stack.
- **Agent** (`zunnel-agent`, any OS Zig targets, no libc) dials each flow with normal sockets.
  Destinations in the proxy's `-localhost-net` (default `240.0.0.0/4`) reach the agent's
  own `127.0.0.1`.
- **Listeners** open a TCP or UDP port on an agent. Each connection is relayed back and dialed
  from the proxy host, e.g. for reverse shells, file transfers, or relays.
- **Relays** (multi-hop): `relay <agent>` exposes the proxy's own port on that agent, so a deeper
  agent can connect through it. Each hop is its own end-to-end encrypted session and can drive
  its own TUN interface.
- **Link** is a single TCP connection secured with
  `Noise_NKpsk0_25519_ChaChaPoly_BLAKE2s` (pure `std.crypto`). The agent pins the proxy's
  public key, and an optional shared secret authenticates the agent. Flows are multiplexed
  with per-flow, credit-based flow control.
- lwIP is fetched by the Zig package manager. Three one-line patches, applied at build time
  by `tools/patch.zig`, make it accept any destination IP and port.

## Build

Requires Zig 0.15.2.

```sh
zig build -Drelease                                                      # host (ReleaseSafe)
zig build -Drelease -Dtarget=x86_64-linux-musl --prefix zig-out/linux    # static Linux binaries
zig build -Drelease -Dtarget=x86_64-windows --prefix zig-out/windows     # Windows binaries
zig build test                                                           # unit + fuzz-corpus tests
zig build fuzz --fuzz                                                    # coverage-guided fuzzing (Linux; see below)
```

Binaries go to `zig-out/bin/` (use `--prefix zig-out/<name>` to keep per-target builds apart).
`-Drelease` builds `ReleaseSafe`. Both binaries parse untrusted network input, and `ReleaseSmall`
/ `ReleaseFast` remove the bounds and overflow checks that turn parser bugs into clean crashes
instead of memory corruption. The frame parser, message decoders, packet parsers and handshake
reader all have fuzz tests. Fuzzing has its own step because Zig 0.15's experimental fuzzer
can't instrument the proxy test binary (it links libc and lwIP); `zig build fuzz` builds only the
pure-Zig parsers. Run it as a normal user, not with `sudo`.

## Privileges

| | Proxy (operator machine) | Agent (target) |
|---|---|---|
| Needs root / Administrator | **Yes**: it creates the TUN interface | **No, never** |
| Needs `wintun.dll` | Yes, on Windows | **No** |
| Files to deploy | `zunnel-proxy` (+ `wintun.dll` on Windows) | the single `zunnel-agent` binary |

The proxy always runs elevated with a TUN, and refuses to start otherwise (on Windows it also
checks for `wintun.dll`). On Linux, a TUN pre-created for your user (`sudo ip tuntap add user
$USER mode tun <name>`) also works. The agent is a multiplexer that turns proxy requests
into ordinary socket calls (`connect`, `send`, `recv`), so it works as any normal user. Without
privileges, the agent has these limits:

- Listeners on ports below 1024 need root or `CAP_NET_BIND_SERVICE` on Linux/macOS (Windows has no such restriction).
- Ping on Linux uses unprivileged ICMP sockets when `net.ipv4.ping_group_range` allows it (the
  default on Fedora and Ubuntu), otherwise it falls back to the system `ping` binary. Windows
  uses `IcmpSendEcho`, which needs no rights.

## Usage

```sh
# operator machine (root, or a pre-created TUN: sudo ip tuntap add user $USER mode tun zunnel)
zunnel-proxy -route 10.10.0.0/16 -autostart

# remote host: copy the agent command the proxy prints (it includes the key and secret)
zunnel-agent -connect proxy.example.com:11601 -pubkey <key> -secret <secret> -retry
```

On first run the proxy writes `zunnel.key`, which holds its private key and a generated shared
secret, and `zunnel.cert` + `zunnel.cert.key`, a self-signed TLS certificate. The link is TLS 1.3
by default: a new connection looks like HTTPS on the wire. `-no-tls` on both ends keeps raw TCP.
The banner prints the full agent command and a matching baked-build command.

Without `-autostart`, use the console (`help` lists everything):

```
zunnel> sessions                                   # connected agents, with their IDENT
zunnel> start 1                                    # route the default iface through agent #1
zunnel> route add 10.10.0.0/16
zunnel> ifaces                                     # interfaces, agents, routes, flow counts
```

Wherever a command takes an `<agent>`, use its session number or a unique prefix of its IDENT, a
stable id derived from the agent's host and user.

In a terminal the console has line editing:
- **Tab** completes commands, interface names, agent ids and IDENTs, and listener ids.
- **↑/↓** browse history, which is kept in `~/.zunnel_history`.
- **←/→, Home/End, Delete, Ctrl-A/E/U/K/W** edit the line, **Ctrl-L** clears the screen, and
  **Ctrl-D** on an empty line exits (**Ctrl-C** shuts down cleanly too).

Messages that arrive while you type, such as an agent joining, are printed above your input line
without disturbing it. With piped or redirected input the console falls back to plain line
reading.

### Seeing what's going on

```
zunnel> ifconfig 1                                 # agent's interfaces, gateway, and suggested routes
zunnel> session info 1                             # ident, host, pid, uptime, link bytes, tunnels, listeners
zunnel> flows                                      # live connections with up/down byte counts
zunnel> ifaces                                     # per-interface totals and dial outcomes
```

`ifconfig` lists the networks the agent can reach as ready-to-run `route add` commands, and marks
the one that carries the agent's own link to the proxy, which you must not route. Events (agents
joining or leaving, routes, interfaces, bindings, listeners, `kill`) are printed with the time.
`-log ops.log` also appends them, with full UTC timestamps, to a file.

### Reconnecting agents

`start` binds the interface to the agent's IDENT, and listeners belong to the IDENT too. When an
agent drops and comes back (`-retry`), its interfaces re-attach and its listeners restart
automatically, with no console input.

```
zunnel> bind dmz 36dec464a84b9acc                  # works even while that agent is offline
zunnel> bindings
zunnel> unbind dmz                                 # `stop dmz` detaches and unbinds
```

### Saving the setup

```
zunnel> save ops.conf                              # interfaces, routes, bindings, listeners
```

`save` writes the setup as console commands. Start the proxy with `-config ops.conf` to replay it;
everything bound attaches as soon as its agents connect.

### Agent lifetime

```
zunnel> kill 36dec4                                # agent shuts down for good, even with -retry
```

`zunnel-agent -expire 72h` (or `-expire 2026-10-20T18:00Z`) stops the agent for good at that
point. `sessions` shows the time left.

Several agents at once, each with its own interface:

```
zunnel> iface add dmz
zunnel> start 2 dmz
zunnel> route add 172.16.0.0/16 dmz
```

Listeners (connections to the agent's port are dialed from the proxy host):

```
zunnel> listener add 1 tcp 0.0.0.0:4444 127.0.0.1:4444   # reverse shell catcher
zunnel> listener add 1 udp 0.0.0.0:53 10.0.0.53:53
zunnel> listeners
zunnel> listener del 1
```

Pivoting deeper: agent #1 can reach a network where agent #2 runs, but the proxy can't reach it:

```
zunnel> relay 1                                    # agent #1 listens on 0.0.0.0:11601
# on the deeper host:  zunnel-agent -connect <agent-1-ip>:11601 -pubkey <key> -secret <secret>
zunnel> sessions                                   # agent #2 shows "via agent #1"
zunnel> iface add deep
zunnel> start 2 deep
zunnel> route add 10.20.0.0/16 deep
```

Traffic to agent #2 is encrypted twice while it crosses agent #1: once for agent #1's link,
once for agent #2's own end-to-end session.

`route add` refuses a network that contains an agent's own link address, because routing it into
the tunnel would cut that agent off. Append `force` to override.

`exit`, Ctrl-C and SIGTERM shut down cleanly: routes, interfaces and firewall rules are removed and
agents are disconnected (`-retry` agents reconnect when the proxy comes back).

### Proxy options

| Option | Default | |
|---|---|---|
| `-listen <addr:port>` | `0.0.0.0:11601` | where agents connect |
| `-key <file>` | `zunnel.key` | private key and shared secret, created if missing |
| `-secret <s>` | from key file | override the shared secret agents must present |
| `-no-secret` | off | accept agents without a secret (warns at startup and on every join) |
| `-no-tls` | off | accept raw TCP only (agents then also need `-no-tls`; warns at startup) |
| `-cert <file>` | `zunnel.cert` | TLS certificate (PEM); self-signed and written on first run |
| `-cert-key <file>` | `zunnel.cert.key` | TLS private key (PEM); generated with the cert |
| `-config <file>` | | run console commands from a file at startup (see `save`) |
| `-log <file>` | | append timestamped events and log lines to a file |
| `-v` / `-q` | | verbose (debug) / quiet (warnings and events only) |
| `-tun <name>` | `zunnel` | default interface name |
| `-route <cidr>` | | route a network through the default interface (repeatable) |
| `-autostart` | off | create the default interface at startup and attach the first agent |
| `-localhost-net <cidr>` | `240.0.0.0/4` | destinations here reach the agent's `127.0.0.1` |
| `-dial-timeout <ms>` | `3000` | how long the agent tries to connect before reporting *filtered* |
| `-max-dials <n>` | `256` | connects in flight per interface; extra SYNs queue (up to 8192) |

### Agent options

Each setting comes from a flag, then a `ZUNNEL_*` environment variable, then a value baked in at
build time. An agent built with its settings baked in runs with **no arguments**, so nothing
sensitive shows up in process listings.

| Flag | Environment | Build option | |
|---|---|---|---|
| `-connect <host:port>` | `ZUNNEL_CONNECT` | `-Dagent-connect=` | proxy address |
| `-pubkey <key>` | `ZUNNEL_PUBKEY` | `-Dagent-pubkey=` | expected proxy key |
| `-secret <s>` | `ZUNNEL_SECRET` | `-Dagent-secret=` | shared secret |
| `-expire <when>` | `ZUNNEL_EXPIRE` | `-Dagent-expire=` | stop for good at a UTC time or after a duration |
| `-id <id>` | `ZUNNEL_ID` | `-Dagent-id=` | override the host-derived IDENT |
| `-retry` | | `-Dagent-retry=` | reconnect forever (on by default for baked agents) |
| `-no-tls` | | `-Dagent-no-tls=` | use raw TCP; the proxy needs `-no-tls` too |
| `-tls-verify` | | `-Dagent-tls-verify=` | require the proxy's TLS cert to match `-connect`'s host |
| `-ca <file>` | `ZUNNEL_CA` | `-Dagent-ca=` | PEM CA bundle used with `-tls-verify` |
| `-q` | | | print nothing |
| `-v` | | | verbose: also log each failed dial and port-unreachable |

```sh
zig build -Drelease -Dtarget=x86_64-windows --prefix zig-out/op1 \
  -Dagent-connect=proxy.example.com:11601 -Dagent-pubkey=<key> -Dagent-secret=<secret> -Dagent-expire=7d
```

Two extra build options help deploy an unattended Windows agent:

- `-Dagent-windowed=true` builds the exe with the Windows GUI subsystem, so no console window
  appears when the agent runs. Log output is silenced; use `-v` from a terminal to see it.
- `-Dagent-service=true` adds `install-service` and `uninstall-service` subcommands and lets
  the Service Control Manager run the exe. Install from an elevated shell:
  ```
  zunnel-agent.exe install-service        # register auto-start LocalSystem service
  sc start ZunnelAgent                     # or wait for the next reboot
  zunnel-agent.exe uninstall-service       # remove it
  ```
  The service uses the baked-in config exclusively (SCM forwards no arguments), so build the
  agent with `-Dagent-connect`/`-Dagent-pubkey`/`-Dagent-secret` before installing.

### Windows notes

The proxy needs Administrator rights and `wintun.dll` (from https://www.wintun.net) next to
`zunnel-proxy.exe`. Interfaces get addresses `198.18.0.1/32`, `198.18.0.2/32`, and so on, skipping
any already in use, so several proxies can run on one machine. Each interface gets a firewall rule
allowing inbound ICMP destination-unreachable to its own address only (new adapters are on the
Public profile, which drops it), and the rule is removed with the interface. The proxy's listening
port is opened with `SO_EXCLUSIVEADDRUSE`, so no other local program can take it over.

Windows refuses to send to `240.0.0.0/4`, so on Windows pick another network to reach the agent's
localhost:

```
zunnel-proxy -autostart -localhost-net 198.18.255.0/24 -route 198.18.255.0/24 -route 10.10.0.0/16
```

## Reliability

- **Heartbeat:** both ends ping every 10 s and drop the link after 30 s of silence, so dead links
  (NAT timeouts, a frozen or killed peer) are noticed quickly and `-retry` agents reconnect.
- **Bounded dials:** the agent connects with a timeout (`-dial-timeout`), at most `-max-dials`
  connects run per interface, and further SYNs queue instead of spawning more work. A 2,000-port
  burst finishes in about 16 s with one agent connect per port.
- **Event-driven I/O:** the relay (both sides) runs on one `poll`/`WSAPoll` thread per link, so
  concurrent flows cost dozens of bytes of state instead of 256 KiB stacks. A 1,000-flow scan
  used to allocate ~750 MB of stack across threads; it now sits at a handful of threads total.
  The thread sleeps while nothing happens, and a connection's socket is closed as soon as both
  directions have finished or either side resets.
- **Backpressure:** a receiver slower than the tunnel slows the sender down through the per-flow
  credit window instead of getting its connection reset. A socket error ends only the connection
  it happened on, never the agent or proxy.
- **Bounded handshakes:** at most 64 handshakes are in progress (8 per source address), each with a
  10 s timeout.
- **Monotonic timers:** heartbeats and every connection timeout run on a monotonic clock, so
  changing the system time (an NTP correction, a VM resuming) doesn't drop links or stall timers.
  Only log timestamps and `-expire` use the wall clock.
- **TLS 1.3 by default:** every new link looks like HTTPS on the wire. The TLS and Noise
  handshakes together must complete within the 10 s handshake timeout. Noise still authenticates
  the proxy inside TLS, so the self-signed cert is enough; `-tls-verify` and `-ca` enable a real
  cert check for operators who want TLS to look like a normal HTTPS client.

## Scanning through the tunnel

Tools should see what they would see on a VPN inside the target network. The agent has no
privileges, so every TCP probe becomes a real `connect()` from the agent host, and the proxy
translates the result back into packets:

| What happened on the agent | What your tool sees | nmap reports |
|---|---|---|
| Connection accepted | SYN-ACK | open |
| Connection refused | RST | closed |
| Timed out (`-dial-timeout`) | nothing | filtered |
| Host / network unreachable | ICMP destination unreachable | filtered / host down |
| Blocked locally on the agent | ICMP admin-prohibited | filtered |
| UDP port closed | ICMP port unreachable | closed (`-sU`) |
| Stray ACK for no connection | nothing | (no false "host up") |

- `-sT`, `-sS`, `-sU`, `-sV`, NSE and default host discovery work. `-sS` behaves like `-sT`: the
  target sees a full TCP connection from the agent for each open port.
- Failed dials are cached for 10 s, so retransmitted SYNs get the same answer without another dial.
- Large UDP datagrams (DNS over UDP with EDNS, QUIC, nmap's `-sU --data-length`) are supported in
  both directions: the proxy reassembles IPv4 fragments arriving from the TUN and fragments
  oversized replies before writing them back. Up to the IPv4 UDP maximum of 65,507 bytes.
- Not possible through any unprivileged pivot: `-sA/-sF/-sN/-sX/-sW`, `-O`, `--traceroute`.

## Done

- [x] TCP/UDP tunnelling through lwIP, with SYNs held until the agent's dial succeeds
- [x] ICMP echo through the agent
- [x] Listeners (TCP + UDP)
- [x] Multiple simultaneous tunnels
- [x] Multi-hop relays
- [x] P0 reliability and safety: heartbeat, dial timeouts and caps, bounded handshakes, route
  guard, fuzz tests, graceful shutdown, startup checks
- [x] P0 VPN-accurate scanning: stray packets dropped, failure-specific answers (RST / silence /
  ICMP unreachable), UDP closed ports, SYN queueing
- [x] P1 operations (part 1): agent config without arguments (flags > env > baked), stable
  host-derived agent identity, `kill` and `-expire`, shared secret by default, interface bindings
  and listeners that survive reconnects, `save` / `-config`
- [x] P1 operations (part 2): agent `ifconfig` with route suggestions, `session info`, `flows` and
  byte counters, timestamped logging and `-log`
- [x] P1 operations (part 3): console line editing, history, tab completion, and async output
  that redraws around the input line
- [x] Review fixes: agent shutdown race, connection timeouts measured per state, connections the
  client abandons early cleaned up at once, monotonic timers
- [x] P2 transports (part 1): TLS 1.3 transport (mbedTLS on the proxy, `std.crypto.tls.Client`
  on the agent, self-signed cert on first run, `-tls-verify` for a real cert check), and the
  ZNL6 wire with no cleartext magic and record padding
- [x] P2 Windows deployment: `-Dagent-windowed` builds a GUI-subsystem agent (no console window),
  `-Dagent-service` adds `install-service`/`uninstall-service` subcommands and SCM dispatch
- [x] P3 scale (part 1): IPv4 fragment reassembly and outbound fragmentation on the TUN,
  single-record UDP datagrams up to 65 KiB, and a reactor-driven relay that replaces the per-flow
  thread model with one `poll`/`WSAPoll` thread per link
- [x] P3 review fixes: finished and reset connections are released at once (the relay thread
  no longer spins on their sockets), reads on drained Windows sockets no longer reset the flow,
  aborted dials return their slot, slow receivers get backpressure instead of a reset, and send
  and connect errors that Zig's std wrappers treat as impossible no longer crash the process

## Roadmap

### P1: operations
- [x] **Stable agent identity.** A reconnecting agent automatically gets back its interfaces and listeners.
- [x] **Agent config without arguments.** Flags > `ZUNNEL_*` environment > values baked in at
  build time (`-Dagent-connect=… -Dagent-pubkey=… -Dagent-secret=…`). Also the prerequisite for a
  possible agent DLL build (see Potential future plans).
- [x] Shared secret by default (generated into the key file); `-no-secret` warns loudly.
- [x] Proxy config file: `save` writes interfaces, routes, bindings and listeners; `-config` restores them.
- [x] `kill <agent>`, and an optional agent `-expire <time>` for engagement windows.
- [x] Agent `ifconfig` (interfaces, addresses, gateway, suggested routes) and `session info`.
- [x] `flows [iface]` command, plus per-flow, per-interface and per-link byte counters.
- [x] Timestamped (UTC) logging, `-log <file>`, `-v`/`-q`, and an event log (joins, leaves, routes, listeners).
- [x] Console line editing, history and tab completion.
- [x] Console output that doesn't interleave with the prompt.

### P2: transports and evasion
- [x] TLS 1.3 transport on top of the Noise link (default on; `-no-tls` keeps raw TCP).
- [x] Less distinctive handshake: no cleartext magic, record padding to fixed-size buckets.
- [x] Windows agent built without a console window (`-Dagent-windowed`); optional run-as-service
  (`-Dagent-service` with `install-service`/`uninstall-service`).
- [ ] WebSocket transport and HTTP CONNECT proxy traversal (with auto-detection on Windows).

### P3: protocol coverage and scale
- [x] IPv4 fragment reassembly and outbound fragmentation on the TUN; UDP datagrams up to 65 KiB.
- [x] Event-driven relay: one `poll`/`WSAPoll` thread per link, no per-flow threads. (A future
  pass may swap `poll` for epoll on Linux and IOCP on Windows if the lab shows the readiness scan
  is a bottleneck.)
- [ ] IPv6 (lwIP dual stack, IPv6 routes on the TUN).
- [ ] kqueue reactor for macOS; a macOS proxy (`utun`).
- [ ] In-repo integration lab (`lab.sh` with network namespaces) and CI cross-compiling Linux,
  Windows and macOS.
