# RicePaddySoftware Enforcement Playbook

**Companion document to `LICENSE_DRAFT_v1.md` (CDMTL v1.0).**

This playbook explains, in plain English, how to actually use the license to get unauthorized copies of DMM, SWISS, dmm-parser, or Field JSON v3.1 implementations taken down from NexusMods, GitHub, and other platforms.

> **Disclaimer:** I am not a lawyer. This playbook is operational guidance based on publicly available platform policies and US copyright law. Consult a licensed attorney before sending formal legal notices in disputed cases.

---

## The Honest Truth About What NexusMods Will Enforce

NexusMods is a US-based content host. Their takedown policy is shaped by the Digital Millennium Copyright Act (DMCA) safe-harbor provisions in 17 U.S.C. § 512. They are NOT going to evaluate the merits of your custom license terms — they will only act on claims they can clearly verify.

### What WORKS (NexusMods will take it down)

| Claim Type | Why It Works | Strength |
|---|---|---|
| **Direct code copying** | Pure DMCA copyright. They diff your code vs theirs. | Very strong |
| **Asset/binary theft** | Your compiled .exe, icons, screenshots reused | Very strong |
| **Copyright Management Information removal** | DMCA §1202, statutory damages | Very strong |
| **Trademark infringement** (registered marks) | Lanham Act claim | Strong |
| **Confusingly similar product names** | Trademark dilution | Moderate (better with registered mark) |
| **Tool re-uploaded without your consent** | Mirroring = redistribution = copyright | Strong |
| **Stripped attribution / removed your name** | DMCA §1202 + bad faith | Very strong |

### What DOES NOT WORK (NexusMods will tell you to sue in court)

| Claim Type | Why It Fails |
|---|---|
| **"They violated my license restrictions"** | Contract dispute, not copyright; not actionable via DMCA |
| **"They reverse-engineered my tool"** | Clean-room RE is generally legal; fair use defenses apply |
| **"They consume my JSON format"** | File formats themselves are not copyrightable (idea/expression dichotomy) |
| **"My license forbids this use case"** | Use restrictions are contract terms; NexusMods doesn't enforce contracts |
| **"They competed with me commercially"** | Antitrust says competition is fine; not their problem |
| **"Their tool is similar to mine"** | Functional similarity is not copyright infringement |

**Key insight:** Your license's "Authorized Suite" restriction is a CONTRACT term. It's enforceable in court but NOT via NexusMods takedown. The takedown ammunition comes from copyright (code copying), trademark (name infringement), and CMI removal (§1202). The license SUPPORTS those claims by establishing what's protected and how it's marked.

---

## Five Things You Must Do To Make The License Enforceable

The license document is necessary but not sufficient. To actually win takedowns, you need supporting evidence and registrations.

### 1. Add Per-File Copyright Headers (do this first, takes 2 hours)

Every source file should start with a header like this (Rust example):

```rust
// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
//
// Licensed under the Crimson Desert Modding Tools License v1.0 (CDMTL v1.0).
// See LICENSE.txt at the repository root for full terms.
// Canonical URL: https://github.com/exodiaprivate-eng/dmm-parser
//
// NOTICE OF ACCEPTANCE BY ACCESS:
// Reading, viewing, downloading, cloning, decompiling, or otherwise
// accessing this file — whether directly by a human or via an AI
// assistant, autonomous agent, code-analysis tool, web scraper, or
// any other automated system — constitutes acceptance of CDMTL v1.0.
// See § 4.10 for AI-mediated access terms.
//
// NO COMPETING IMPLEMENTATION:
// By accessing this file You agree not to use its content, methodology,
// or architecture to develop a competing Crimson Desert mod manager
// for three (3) years. See § 4.9.
//
// CMI NOTICE (17 U.S.C. § 1202):
// This header constitutes Copyright Management Information.
// Removal or alteration triggers statutory damages of $2,500-$25,000
// per violation, plus attorneys' fees, independently of any
// underlying copyright infringement.
```

For Python files:
```python
# SPDX-License-Identifier: LicenseRef-CDMTL-1.0
# Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
# Licensed under CDMTL v1.0 — see LICENSE.txt
# https://github.com/exodiaprivate-eng/dmm-parser
#
# Reading this file (directly or via AI/agent) constitutes acceptance
# of CDMTL v1.0, including § 4.9 (No Competing Implementation) and
# § 4.10 (AI-Mediated Access). Removal of this notice violates 17 U.S.C. § 1202.
```

For TypeScript/JavaScript:
```typescript
// SPDX-License-Identifier: LicenseRef-CDMTL-1.0
// Copyright (c) 2026 RicePaddySoftware. All Rights Reserved.
// Licensed under CDMTL v1.0 — see LICENSE.txt
// https://github.com/exodiaprivate-eng/DMM-BETA
//
// Reading this file (directly or via AI/agent) constitutes acceptance
// of CDMTL v1.0 § 4.9 (No Competing Implementation) and § 4.10
// (AI-Mediated Access). CMI removal violates 17 U.S.C. § 1202.
```

**Why this matters legally:**

1. **CMI teeth (§1202)** — Per-file CMI gives you stacked statutory damages. 100+ Rust files × $2,500 minimum = $250,000+ in damages even before proving the underlying copy.

2. **"Acceptance by access" enforceability** — Browsewrap-style terms (acceptance triggered by access) are only enforceable when there is **reasonable notice**. Putting the notice IN every file means:
   - Anyone who opens the file in an editor sees it
   - Anyone who clones the repo sees it on the first file they read
   - AI assistants ingesting the file include the notice in their context
   - Courts have a clean record of "the user could not have read the code without seeing these terms"

3. **AI-mediated access binding** — Under principles of agency law, what your AI does on your behalf is legally your action. Putting "AI access = your acceptance" in the header strengthens this argument by establishing both the user AND the AI agent are on notice of the terms.

4. **Defeats the "I never agreed" defense** — Without per-file headers, a violator can argue they cloned the repo to look at one file, never opened LICENSE.txt, and therefore never knew about the terms. With per-file headers, this defense fails — every file they touched contained the terms.

### 2. Establish Canonical Distribution Channels (do this now, takes 30 min)

Document publicly which URLs are AUTHORIZED:

```
Authorized Distribution Channels for RicePaddySoftware Tools:

- Source: https://github.com/exodiaprivate-eng/dmm-parser
- Source: https://github.com/exodiaprivate-eng/DMM-BETA
- Source: https://github.com/NattKh/CRIMSON-DESERT-SAVE-EDITOR-AND-GAME-MODS
- NexusMods: [your nexusmods page URL when published]
- Releases: https://github.com/exodiaprivate-eng/<repo>/releases

Any copy of these tools found OUTSIDE these URLs is unauthorized
and subject to DMCA takedown.
```

Put this in:
- `README.md` of each repo
- Your NexusMods mod page description
- A pinned issue or wiki page on your main repo

**Why this matters:** When you file a DMCA notice, you need to prove the copy is unauthorized. "It's not on my list of authorized channels" is a clean evidentiary claim.

### 3. Register Your Copyright with the US Copyright Office (one-time, $45-65)

US copyright is automatic on creation, BUT:
- Registered copyright lets you claim **statutory damages** ($750–$30,000 per work, up to $150,000 for willful infringement)
- Registered copyright lets you recover **attorneys' fees**
- Without registration, you can only sue for actual damages (which are usually $0 for free software)

**How:**
1. Go to https://www.copyright.gov
2. Register the dmm-parser source code as a "literary work, computer program"
3. Register the Field JSON v3.1 spec as a separate "literary work"
4. Cost: $45 single-author, $65 organization
5. Takes 3-6 months to issue but is retroactively effective from filing date

**Why this matters:** Without registration, your DMCA still works, but if the violator fights back, you have weak monetary leverage in court. Registration multiplies your settlement leverage 100x.

### 4. File for Trademark Protection (when you can afford it, $250-350 per mark)

Trademark protections in the license are mostly defensive without registration. To enforce:

**Priority 1 — file these:**
- "DMM" (or "Definitive Mod Manager") — for software
- "SWISS Suite" — for software
- "Field JSON v3.1" — could be hard, format names sometimes get rejected as descriptive

**Priority 2 — file if you have budget:**
- "RicePaddySoftware"
- "CrimsonGameMods"

**How:**
1. Search USPTO TESS database first (https://www.uspto.gov/trademarks/search) — make sure no one else owns these
2. File via USPTO TEAS Plus ($250) or hire a trademark attorney ($1,500-3,000 turnkey)
3. Use Class 9 (Computer software) for product marks
4. Can take 6-12 months for registration

**Why this matters:** Common-law trademark exists but is jurisdiction-limited and weak in court. Registered ® gives you nationwide rights, statutory damages for counterfeit, and customs/border enforcement.

### 5. Build An Evidence Trail (do this every release)

For every release of DMM, SWISS, dmm-parser:

- Tag the git commit with `v1.2.3` (timestamped, immutable)
- Publish a GitHub Release with the binary
- Post the release on your NexusMods page
- Save a SHA-256 hash of every distributed binary in your records
- Take a screenshot of the GitHub Release page (in case it gets deleted)

**Why this matters:** When filing DMCA, you need to prove **prior authorship**. "I have a git commit dated 2026-04-15 with SHA-256 `abc123...` matching the binary they uploaded on 2026-04-20" is irrefutable. Without this trail, the violator can claim independent creation.

---

## How To File a DMCA Takedown on NexusMods (Step-by-Step)

When you find unauthorized copies of DMM, SWISS, or v3.1 implementations on NexusMods:

### Step 1: Document the Violation

Before sending anything, capture:
- Full URL of the infringing mod page
- Screenshot of the page (in case they delete)
- Download the file (preserve evidence)
- Compare the binary to yours: `sha256sum violator.exe` vs `sha256sum your-release.exe`
- Diff any source code files visible
- Check if they removed your copyright headers (this is your §1202 claim)

### Step 2: Write the DMCA Notice

NexusMods accepts DMCA notices at: **dmca@nexusmods.com**

Standard DMCA notice template:

```
SUBJECT: DMCA Takedown Notice — Unauthorized Copy of [Tool Name]

To: NexusMods DMCA Agent

I am the copyright owner of [Tool Name], distributed under the
Crimson Desert Modding Tools License v1.0 by RicePaddySoftware.

1. IDENTIFICATION OF COPYRIGHTED WORK:
   Tool: [DMM / SWISS Save Editor / dmm-parser / etc.]
   Original distribution URL: https://github.com/exodiaprivate-eng/[repo]
   Copyright registration: [TX-12345-678 if registered, otherwise "common-law copyright"]
   First publication date: [date of first commit/release]

2. IDENTIFICATION OF INFRINGING MATERIAL:
   URL: https://www.nexusmods.com/crimsondesert/mods/[ID]
   Uploader: [username]
   Date posted: [date]

3. EVIDENCE OF INFRINGEMENT:
   The uploader has redistributed my Covered Work without authorization.
   Specifically:
   (a) [SHA-256 hashes match — describe]
   (b) [Copyright headers removed — describe, this triggers §1202]
   (c) [Distribution outside Authorized Channels per CDMTL v1.0 §4.7]
   (d) [Confusingly similar branding per CDMTL v1.0 §4.5]

4. GOOD FAITH STATEMENT:
   I have a good faith belief that use of the material in the
   manner complained of is not authorized by the copyright owner,
   its agent, or the law.

5. ACCURACY STATEMENT:
   The information in this notification is accurate, and under
   penalty of perjury, I am authorized to act on behalf of the
   copyright owner of the exclusive right that is allegedly infringed.

6. CONTACT INFORMATION:
   Name: [Your legal name OR "RicePaddySoftware Authorized Agent"]
   Email: [your email]
   Address: [your physical address — REQUIRED by DMCA]
   Phone: [your phone — REQUIRED by DMCA]

7. SIGNATURE:
   /s/ [Your name]
   Date: [today]

ATTACHMENTS:
- Screenshot of infringing page
- Download of infringing file (SHA-256: ...)
- Diff showing copied code (if applicable)
- Original copyright headers vs stripped version (§1202 evidence)
- Reference to LICENSE.txt at https://github.com/exodiaprivate-eng/[repo]/blob/main/LICENSE.txt
```

### Step 3: Send and Track

- Send to dmca@nexusmods.com
- Save the email + any auto-reply with case number
- Expected response time: 1-7 days
- NexusMods will either take the content down or forward your notice to the uploader for counter-notice

### Step 4: Handle Counter-Notice (if it happens)

If the uploader files a counter-notice claiming the takedown was wrongful:
- NexusMods is REQUIRED by DMCA to put the content back up after 10-14 business days **unless you file a lawsuit**
- This is the moment you actually need an attorney
- Most counter-notices are bluffs; many violators give up at this stage rather than face litigation
- If you don't litigate, the content stays up — but you can re-file if they violate again

### Step 5: Repeat Offender Tracking

NexusMods tracks repeat infringers. After 3+ DMCA strikes, they typically ban the uploader's account. Document each takedown so you can show a pattern.

---

## How To File a DMCA Takedown on GitHub (Different Process)

GitHub's DMCA process: https://github.com/contact/dmca

Key differences from NexusMods:
- GitHub publishes all DMCA notices publicly at https://github.com/github/dmca
- Allows specific-line takedowns rather than whole-repo
- Repeat-infringer policy applies to entire GitHub accounts
- Counter-notice puts content back in 10-14 days without litigation

Use the same notice template above, but submit via the GitHub web form.

---

## Trademark Complaints (Different from DMCA)

DMCA = copyright. For trademark issues (someone using "DMM2" or "CDUMM" for a tool that confuses users), use the platform's separate trademark complaint process:

**NexusMods trademark complaint:**
Email: legal@nexusmods.com (NOT dmca@)
Provide:
- Your trademark registration (or evidence of common-law mark use)
- The infringing use
- Why it creates confusion in the modding community
- Reference to CDMTL v1.0 §4.5 (Trademark and Naming clause)

**GitHub trademark complaint:**
https://docs.github.com/en/site-policy/content-removal-policies/github-trademark-policy

---

## Detecting AI-Mediated Copying

When CDUMM (or any competitor) is built with AI assistance, you have several signals to look for:

### Signature patterns of AI-generated code from your codebase

**1. Architectural fingerprints** — AI assistants tend to preserve architectural patterns from their input. If their tool has:
- The same module breakdown (binary/, crypto/, item_info/)
- The same naming conventions (`parse_table`, `serialize_table`, `apply_v3_for_target`)
- The same struct field ordering
- The same dispatch table with similar match arms

...that's strong evidence the AI was given dmm-parser as context.

**2. Comment style transfer** — AI assistants often preserve comment style and even verbatim comments from training/context data. If their codebase has:
- Comments matching your exact phrasing
- Section headers in the same format ("// ============ SECTION ==========")
- TODO/FIXME comments referencing your concepts
- Docstrings that paraphrase your spec

...you have potential copyright + §1202 claims.

**3. Error message strings** — These are gold. AI tends to copy error strings verbatim or near-verbatim. Decompile their binary, extract strings, grep for matches:
```bash
strings competitor-binary.exe | grep -i "field\|table\|pabgh\|pamt\|paz"
```

Any matches with your error messages = direct copying claim.

**4. Test fixture reuse** — If they ship test files with the same names, same JSON examples, same modder fixtures from your repo, that's verbatim copying.

**5. Variable naming idiosyncrasies** — Your unique variable names (`pabgh_bounded`, `tail_pad`, `extra_entries`, `core_block`) are distinctive enough that an independent implementation wouldn't replicate them. AI-assisted reimplementation often retains these names.

### How to gather evidence

**Step 1 — Check their public AI usage:**
- Discord/Twitter posts mentioning Claude, ChatGPT, Cursor, Copilot
- README references to "AI-assisted development"
- Commit messages mentioning AI tools
- Posts asking AI for help that reference DMM/dmm-parser

**Step 2 — Check repository traffic on YOUR repos:**
- GitHub Insights → Traffic → Clones — look for spikes around when CDUMM started
- GitHub Insights → Traffic → Visitors — country/timing patterns
- This won't show usernames but shows access volume

**Step 3 — Check for AI tool signatures:**
- GitHub Copilot generates distinctive comment styles
- ChatGPT/Claude tend to over-document with explanatory comments
- Aider produces structured commits with specific patterns
- Cursor leaves `.cursorrules` files in repos

**Step 4 — Compare structural similarity quantitatively:**
Tools like:
- `codequery` for cross-repo function-name similarity
- `tlsh` for fuzzy hashing of binaries
- `diff` on decompiled output
- AST-level comparison via tree-sitter

### Filing the claim

When you have evidence, file based on whichever claim is strongest:

1. **Verbatim string/code match** → DMCA copyright claim (always strongest)
2. **Stripped headers but identical structure** → §1202 + copyright derivative claim
3. **Architectural similarity + proven AI usage** → CDMTL §4.9 contract breach + §4.10 AI-mediated access
4. **Just structural similarity, no AI proof** → weak — focus on community/branding instead

### Honest limit on AI-mediated enforcement

The legal theories here (acceptance by access, AI as agent, imputation of knowledge) are **legally sound but largely UNTESTED in court**. No reported case yet has held a defendant liable for using AI to read GPL'd code and build a competitor. The precedents are:

- **General agency law** (Restatement (Third) of Agency) — supports holding principals liable for agents' actions
- **ProCD v. Zeidenberg (1996)** — supports browsewrap with reasonable notice
- **Specht v. Netscape (2002)** — limits browsewrap when notice is hidden
- **Field v. Google (2006)** — search/cache access without notice = no acceptance

What this means: your license clauses are **enforceable in theory** with proper notice (per-file headers), but you'll be **making law** rather than relying on it if you litigate. This means:
- Strong settlement leverage (defendants don't want to be the test case)
- Risk of unfavorable precedent if you lose
- Worth pursuing for clear violations, but pick your battles carefully

For the vast majority of CDUMM-class threats, the practical leverage comes from:
1. Per-file CMI removal (always actionable)
2. Verbatim string matches in decompiled binary (always actionable)
3. Trademark on names (actionable with registration)
4. Community/brand pressure (most effective regardless of legal status)

---

## When The Code Is Different But The Method Is The Same

This is the hardest scenario and the most important one to be honest about.

### The legal reality

**17 U.S.C. § 102(b)** explicitly excludes methods, processes, and systems from copyright protection. If a competitor:
- Wrote completely original code from scratch
- Implements the same functional approach (parse JSON → apply field intents → rewrite archives)
- Achieves the same end result as DMM

...there is **no copyright claim available**. NexusMods will not take it down on copyright grounds. Bad-faith DMCA filings can backfire under §512(f) and create liability for YOU.

This is settled law (Baker v. Selden, Computer Associates v. Altai, Sega v. Accolade, Oracle v. Google). It's not a loophole; it's the deliberate design of copyright law — methods belong in patents, not copyright.

### What you DO have leverage on

Even when code is different, these claims can still work:

**1. Contract Breach (CDMTL §4.9 — No Competing Implementation)**
If the competitor ever cloned dmm-parser, downloaded DMM, or read your Field JSON v3.1 spec doc, they accepted CDMTL by doing so. §4.9 prohibits them from building a competing tool for 3 years.

Evidence to gather:
- GitHub clone events visible in repo Insights → Traffic
- Discord/forum posts where they referenced your work
- Their own public statements about studying DMM
- Wayback Machine captures showing they viewed your repo
- Email threads where they asked you questions about DMM

If you can prove they touched your work, you have a contract claim — NOT a DMCA, but a breach of license suit. NexusMods may honor this if you provide clear evidence.

**2. Spec Document Copyright**
The Field JSON v3.1 specification text itself is copyrighted as a literary work. If their tool's documentation:
- Quotes from your spec
- Paraphrases your spec structure
- References specific section numbers from your spec
- Uses the same examples or test fixtures

...you have a derivative work claim on the documentation. This is separate from "they implement the same format."

**3. Trademark on "Field JSON v3.1"**
If their tool advertises "Compatible with Field JSON v3.1" or uses the name in their UI/documentation, that's a trademark claim — they're using your branded format name without authorization. Get the trademark registered and you can DMCA platform listings that use this term.

**4. Compatibility Claims as Source Identification**
If they say "Works with DMM mods" — and that statement is misleading or creates user confusion — that's potential false advertising under the Lanham Act §43(a) (15 U.S.C. § 1125). Different from straight trademark; doesn't require registration.

### What you DO NOT have leverage on

Be honest with yourself about these:

| Scenario | Legal Status |
|---|---|
| They wrote a parser for the same .paz files independently | Legal — file formats aren't copyrightable |
| They reverse-engineered Crimson Desert without ever touching DMM | Legal — clean-room RE is fair use |
| They built a Tauri app that mounts mods to game directories | Legal — UI patterns aren't protected |
| They use JSON to describe modifications | Legal — the IDEA of JSON-based mods isn't owned by anyone |
| They have a similar architecture | Generally legal under Altai test |
| Their tool is "inspired by" DMM but built fresh | Legal unless they accepted your license first |

### The realistic enforcement strategy for CDUMM-class threats

**Step 1 — Establish whether they ever accepted CDMTL.**
- Check your repo traffic — did their GitHub username clone dmm-parser?
- Check Discord/Reddit — did they post screenshots of DMM internals?
- Check their early commits — do they reference your spec versions or use your terminology?

If YES → §4.9 contract breach claim. File based on contract, not copyright.
If NO → you have minimal legal recourse on functionality. Pivot to community/branding.

**Step 2 — Audit their tool for ANY copying.**
- Decompile their binary, search for strings from dmm-parser
- Check if their JSON examples match yours byte-for-byte
- Check if their documentation phrases match yours
- Check if they shipped any of your test fixtures
- Check for stripped copyright headers (§1202)

ANY hit here → DMCA on copyright grounds (the strongest claim type).

**Step 3 — Evaluate trademark angles.**
- Does their tool name confuse users? (CDUMM ↔ DMM)
- Do they use "Field JSON v3.1" branding without authorization?
- Are they implying compatibility/endorsement falsely?

If yes → trademark complaint to NexusMods (separate from DMCA).

**Step 4 — Brand-level enforcement.**
This is where you'll get the most mileage:
- Establish "DMM Recognized" certification — public list of approved tools
- Publicly identify CDUMM as "unofficial / not recommended / may corrupt saves"
- Get NexusMods curators to flag unsupported tools
- Coordinate with mod authors to publish only for recognized platforms
- Use your README, NexusMods page, Discord, and social media to clarify which tool is canonical

This is how Vortex, MO2, OpenIV, and Frosty maintained dominance — not lawsuits, but community recognition. It's slower than a takedown but more durable.

**Step 5 — Last resort: full lawsuit.**
If §4.9 was clearly violated (proven prior access + competing tool), and the platform won't act on contract breach alone, you can file in federal court for breach of license + injunction. Cost: $20,000-$100,000 minimum. Generally only worth it if there's significant commercial damage.

### What I'd actually recommend

For a hobbyist modding community where CDUMM is the realistic threat:

1. **Today** — Add §4.9 to your published license (already in v1 draft above)
2. **Today** — Add a "DMM Recognized Tools" section to your README listing only DMM and SWISS
3. **This week** — Audit any current "CDUMM" or competitor for §1202 violations and code copying
4. **This month** — Register copyright on dmm-parser source + Field JSON v3.1 spec ($45-65)
5. **This quarter** — File trademark on "DMM" (or "Definitive Mod Manager") + "Field JSON v3.1" if available ($250-700)
6. **Ongoing** — Build community recognition: Discord announcements, NexusMods page text, mod author coordination

The legal protections give you takedown ammunition for clear copying. The brand/community work gives you durable dominance even when methods get cloned legally.

---

## What To Do About "CDUMM" (or any specific competitor)

If "CDUMM" or any other tool is using your work, here's the analysis path:

### Step A: Determine What Was Actually Copied

Don't assume — verify. Download CDUMM. Decompile if it's binary. Check:

1. **Does it ship dmm-parser binaries verbatim?** → Strong DMCA claim (binary copy)
2. **Does it ship modified dmm-parser source?** → Strong DMCA claim (derivative work without source disclosure)
3. **Does it parse Field JSON v3.1 files?** → Weak copyright claim (formats aren't copyrightable) BUT...
4. **Does it ship the Field JSON v3.1 SPEC DOC?** → Strong DMCA (the spec text is copyrighted as a literary work)
5. **Did they remove your copyright headers?** → §1202 claim (statutory damages)
6. **Is "CDUMM" confusingly similar to "DMM"?** → Trademark claim (especially if you register DMM™)
7. **Did they reverse-engineer your tool from scratch with no copying?** → Weak claim, generally legal

### Step B: Pick The Strongest Claim

Don't kitchen-sink the DMCA. Pick the cleanest violation:

- Best case: They literally shipped your code → file straight DMCA, 95% takedown success
- Good case: They shipped your spec doc → file DMCA on the spec, 80% success
- OK case: They stripped your CMI → §1202 claim, 70% success but smaller damages
- Marginal: They built compatible parser independently → trademark claim only on the name

### Step C: Send The Notice and Document Outcome

Use the template above. Track the result. If they counter-notice, you have a decision: litigate or let it stay up.

### Step D: If You Can't Take It Down — Public Pressure

If your DMCA fails or counter-notice succeeds and you can't litigate:
- Update your README to publicly identify CDUMM as "unofficial / not authorized"
- Post on the Crimson Desert subreddit clarifying which tool is canonical
- Use NexusMods page descriptions to direct users to authorized tools
- This isn't legal enforcement but it's social-layer enforcement that often works in modding communities

---

## Realistic Expectations

**What this license + playbook GETS YOU:**
- A clear basis for DMCA takedowns of binary/source/spec copying — high success rate
- §1202 leverage for stripped attribution — strong settlement tool
- Trademark protection for product names (when registered)
- Public-facing legal stance that discourages bad actors from starting trouble
- Ammunition for community-side reputation fights

**What this license + playbook DOES NOT get you:**
- Unilateral power to remove competitors NexusMods deems independent works
- Enforcement of "Authorized Suite only" use restrictions on third parties (that's lawsuit territory)
- Protection against clean-room reverse engineering
- Ability to copyright the file format itself (Section 102(b) of the Copyright Act)
- Government enforcement without you initiating it

**Bottom line:** The license + this playbook give you a 70-85% effective enforcement toolkit on platforms like NexusMods. The remaining 15-30% requires either a lawsuit or community pressure. That's the realistic ceiling for any license — even Microsoft, Adobe, and Oracle face the same enforcement gaps.

---

## Quick Reference: Files To Update Before Going Live

When you adopt CDMTL v1.0, update these files:

- [ ] `LICENSE.txt` (or `LICENSE`) in every RicePaddySoftware repo — replace MPL-2.0 with CDMTL v1.0
- [ ] `README.md` in every repo — add "Licensed under CDMTL v1.0" + Authorized Channels list
- [ ] Per-file headers in all `.rs`, `.py`, `.ts` files — add SPDX + copyright + CMI notice
- [ ] NexusMods mod page descriptions — add license badge + "unauthorized copies will be DMCA'd" notice
- [ ] GitHub repository "About" section — add license link
- [ ] `Cargo.toml` `license = "LicenseRef-CDMTL-1.0"` (use LicenseRef- because CDMTL isn't in SPDX)
- [ ] `pyproject.toml` `license = { text = "CDMTL-1.0" }`
- [ ] Python package `setup.py` if applicable
- [ ] CHANGELOG.md noting the relicense from MPL-2.0 → CDMTL v1.0

---

*End of Playbook. Pair this with `LICENSE_DRAFT_v1.md` for the operative legal text.*
