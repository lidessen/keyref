# docs

Specifications and contracts. `server/`, `cli/` and `ios/` have implementations; when an implementation raises a question, change these documents first, then the code.

The documents below are written in Chinese; commands, field names, algorithms, paths and code identifiers stay English in them, and this index is the English entry point.

| Document | Contents |
| --- | --- |
| [design.md](design.md) | The full design: threat model, architecture, `exec` and the injection shapes, data model, cryptography, recovery and revocation, storage and self-hosting, hosting cost, API, tech stack, roadmap, open questions |
| [protocol.md](protocol.md) | The wire contract: endpoints, request/response examples, the exact transcript byte layout. The only reference both implementations work against. Contains the 2026-11 protocol v2 breaking batch (sections marked "v2 X"; the change spec was merged in and removed) |
| [ios-ui.md](ios-ui.md) | The iOS interaction spec: information architecture, per-screen states and copy, Liquid Glass and accessibility decisions |
| [handoff.md](handoff.md) | State after the 2026-11 review: what was fixed and how far it was verified, confirmed open issues, design problems, and the implementation order |

Suggested reading order: the "decision summary" at the top of design.md first, then the threat model, `exec` and the three injection shapes (§7.8) — those three decide what makes this product different from an ordinary password manager. Read protocol.md end to end before writing any protocol code.
