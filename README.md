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
zig build test --fuzz                                                    # coverage-guided fuzzing (Linux only)
```

Binaries go to `zig-out/bin/` (use `--prefix zig-out/<name>` to keep per-target builds apart).
`-Drelease` builds `ReleaseSafe`. Both binaries parse untrusted network input, and `ReleaseSmall`
/ `ReleaseFast` remove the bounds and overflow checks that turn parser bugs into clean crashes
instead of memory corruption. The frame parser, message decoders, packet parsers and handshake
reader all have fuzz tests.

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
zunnel-proxy -secret s3cret -route 10.10.0.0/16 -autostart

# remote host (key printed by the proxy)
zunnel-agent -connect proxy.example.com:11601 -pubkey <key> -secret s3cret -retry
```

Without `-autostart`, use the console (`help` lists everything):

```
zunnel> sessions                                   # connected agents
zunnel> start 1                                    # route the default iface through agent #1
zunnel> route add 10.10.0.0/16
zunnel> ifaces                                     # interfaces, agents, routes, flow counts
```

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
# on the deeper host:  zunnel-agent -connect <agent-1-ip>:11601 -pubkey <key> -secret s3cret
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
| `-key <file>` | `zunnel.key` | proxy private key, created if missing |
| `-secret <s>` | none | shared secret agents must present (recommended) |
| `-tun <name>` | `zunnel` | default interface name |
| `-route <cidr>` | | route a network through the default interface (repeatable) |
| `-autostart` | off | create the default interface at startup and attach the first agent |
| `-localhost-net <cidr>` | `240.0.0.0/4` | destinations here reach the agent's `127.0.0.1` |
| `-dial-timeout <ms>` | `3000` | how long the agent tries to connect before reporting *filtered* |
| `-max-dials <n>` | `256` | connects in flight per interface; extra SYNs queue (up to 8192) |

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
- **Bounded handshakes:** at most 64 handshakes are in progress (8 per source address), each with a
  10 s timeout.

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

## Roadmap

### P1: operations
- [ ] **Stable agent identity.** A reconnecting agent automatically gets back its interfaces, routes and listeners.
- [ ] **Agent config without arguments.** Bake in the connect address, key and secret at build
  time (`-Dconnect=… -Dpubkey=… -Dsecret=…`) or read them from the environment, so secrets don't
  show up in process listings.
- [ ] Make `-secret` mandatory by default, and warn loudly when it is disabled.
- [ ] Agent `ifconfig` (interfaces and addresses in the hello) and `session info <id>`.
- [ ] `flows [iface]` command, plus per-tunnel and per-agent byte and flow counters.
- [ ] Timestamped logging, `-log <file>`, `-v`/`-q`, and an event log (joins, leaves, routes, listeners).
- [ ] Proxy config file: interfaces, routes and listeners restored on startup.
- [ ] `kill <agent>`, and an optional agent `-expire <time>` for engagement windows.
- [ ] Console line editing, history and tab completion.
- [ ] Console output that doesn't interleave with the prompt.

### P2: transports and evasion
- [ ] Alternate transports: TLS (looks like HTTPS) and WebSocket. Agent support for HTTP CONNECT
  proxies, with auto-detection on Windows.
- [ ] A less distinctive handshake: no cleartext magic, optional random padding, fixed-size records.
- [ ] Windows agent built without a console window; optional run-as-service.

### P3: protocol coverage and scale
- [ ] IPv6 (lwIP dual stack, IPv6 routes on the TUN).
- [ ] IP fragment reassembly and UDP datagrams over 16 KiB, which are currently dropped.
- [ ] Event-driven agent (epoll/kqueue/IOCP) instead of thread-per-flow, for very large scans.
- [ ] macOS proxy (utun).
- [ ] In-repo integration lab (`lab.sh` with network namespaces) and CI cross-compiling Linux,
  Windows and macOS.
