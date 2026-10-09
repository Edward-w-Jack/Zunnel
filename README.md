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
zig build -Doptimize=ReleaseSmall                                  # host
zig build -Doptimize=ReleaseSmall -Dtarget=x86_64-linux-musl       # static Linux binaries
zig build -Doptimize=ReleaseSmall -Dtarget=x86_64-windows          # Windows binaries
zig build test                                                     # unit tests
```

Binaries go to `zig-out/bin/` (use `--prefix zig-out/<name>` to keep per-target builds apart).

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

On Windows the proxy needs Administrator rights and `wintun.dll` (from https://www.wintun.net)
next to `zunnel-proxy.exe`. Interfaces get addresses `198.18.0.1/32`, `198.18.0.2/32`, and so on. Windows refuses to
send to `240.0.0.0/4`, so on Windows pick another network to reach the agent's localhost:

```
zunnel-proxy -autostart -localhost-net 198.18.255.0/24 -route 198.18.255.0/24 -route 10.10.0.0/16
```

## Status / TODO

- [ ] IPv6 (lwIP is built IPv4-only for now)
- [ ] Agent interface listing (`ifconfig` in the console)
- [ ] Dial timeouts on the agent
- [x] ICMP echo through the agent
- [x] Listeners (TCP + UDP)
- [x] Multiple simultaneous tunnels
- [x] Multi-hop relays
