# DMM Parser — License Change Brief

*For community manager review before public communication.*

---

## What's changing

I'm taking the Rust/Python parser library that DMM uses to read game files (`pabgb`, `pabgh`, `paz`, `pamt`, `papgt`) and forking it into a new project called **`dmm-parser`**.

The original library was called `crimson-rs`, written by `potter4208467` (Discord). It was MIT-licensed, meaning anyone could copy it, modify it, and redistribute it — including in tools that compete with DMM. `potter4208467` has given written permission to relicense the fork going forward (2026-04-27).

`dmm-parser` will use a custom **source-available, private-repo** license: the source lives only in a private repo under `exodiaprivate-eng`, never publicly visible.

## Who can use it

**Allowed:**
- The DMM mod loader and any official DMM tooling
- Individuals studying it personally or authoring mods that DMM consumes
- `potter4208467` (original author) and any collaborators he designates

**Not allowed without written consent:**
- Inclusion (in whole, in part, ported to another language, or as a thin wrapper) inside another mod loader, mod manager, archive editor, save editor, or competing end-user tool that targets the same game data
- **Clean-room reverse engineering of DMM** to produce a parser, loader, or compatible tool. This is the key clause: even if the third party never sees `dmm-parser` source, observing DMM's behavior and reimplementing it is explicitly prohibited.
- AI-assisted refactoring or black-box behavioral cloning that ends up at substantial functional equivalence
- Public redistribution of the source, decompiled binaries, screenshots of source, or implementation-detailed summaries

## Why the strategy is "private repo + tight license"

The repo stays private. That removes the easy "I just looked at the source" attack — there's nothing to look at. So any third-party tool that lands on a parser doing what DMM's parser does got there by either:

1. Asking for permission (allowed path)
2. Reverse-engineering DMM's behavior and writing their own (explicitly prohibited by license)
3. Pulling our binary apart and copying / paraphrasing what they find (explicitly prohibited by license)

If a competing tool ships a "1-to-1" parser — and the prediction here is they will, because the alternative is a year of work — that's a clear license violation regardless of which path they took, because all three non-permission paths are covered.

## Credit

Both copyright holders are named in the LICENSE and README:
- **`potter4208467`** — original parser work
- **`exodiaprivate-eng`** — current distribution + extensions (BuffData family, SkillInfo, 100+ table additions)

## Why I'm doing this

The parser represents about a year of reverse-engineering work — finding the right Korean error strings in the game binary, decompiling polymorphic dispatchers, mapping 449 game data tables, tracking down 120 BuffData variants, etc. Right now anyone can take that work, drop it into a competing tool, and ship a mod manager that took ~zero of that effort.

This change doesn't lock down the game files themselves; it locks down the *implementation that took the time to figure them out*.

## What this does NOT do (being honest)

A pure copyright license technically can't prevent every form of clean-room reimplementation — in some jurisdictions, that's a protected activity. The "no reimplementation" clause is enforceable as a *contract term* (anyone with access to the binary or source has implicitly accepted the LICENSE) and as a Nexus policy violation, not necessarily as a copyright infringement claim in court.

In practice that's enough:
- Nexus enforcement doesn't require winning in court — it requires a clear policy violation, which the LICENSE provides.
- GitHub DMCA enforcement against a public repo that contains substantially similar code is straightforward.
- Most third-party developers won't risk it for a hobby project; they'll either ask or stay on the public v3.

## Practical effect for the community

- **Mod authors:** No change. v3 mod format is still publicly documented and supported.
- **DMM users:** No change. The parser is bundled with DMM as it always has been.
- **Third-party tool authors:** Need to either ask permission or stay clear. Ignoring the license = Nexus boot.

## Things I'd appreciate review on

1. Is the "no clean-room reimplementation" clause too aggressive? It's stronger than typical FOSS licenses, intentionally.
2. Is "substantial functional equivalence" defined clearly enough to be enforceable as a Nexus policy violation, or does it need tighter wording?
3. Whether to give a 30-day grace period for any third-party tool currently using `crimson-rs` (the prior MIT-licensed version) to either ask for permission or stop using it.
4. The v4 mod format question — happy to defer that conversation, but flagging that adding cryptographic signing later is an option if license enforcement alone proves leaky.

LICENSE text and README are ready if you want to see them. Source repo will be private under `exodiaprivate-eng`.
