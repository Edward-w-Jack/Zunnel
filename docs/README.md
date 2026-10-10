# zunnel developer documentation

These pages describe how zunnel works inside. For building and using it, see the
[top-level README](../README.md).

| Document | Covers |
|---|---|
| [architecture.md](architecture.md) | How the pieces fit: components, threads and locks, the packet path through the server, sessions and identities, listeners and relays, the relay engine, flow control, limits and timers, build and tests. |
| [protocol.md](protocol.md) | The link wire format (ZNL6): connection setup and handshake, hello, records, frames and payload encodings, flow lifecycles, flow control, heartbeat, versioning. |
| [files.md](files.md) | What each source file handles, with the main types and functions to look at. |

A suggested reading order for new contributors:

1. The "How it works" section of the top-level README.
2. [architecture.md](architecture.md), "Components" and "The link".
3. Whichever path you are changing:
   - "Packet path" in [architecture.md](architecture.md) for server-side traffic.
   - "The relay" in [architecture.md](architecture.md) for socket handling.
   - [protocol.md](protocol.md) for anything that crosses the link.
4. [files.md](files.md), to find the code.

When you change behaviour these pages describe, update them in the same commit. That applies
especially to wire-format changes (bump the prologue version, see
[protocol.md](protocol.md#versioning)) and to limits and timers.
