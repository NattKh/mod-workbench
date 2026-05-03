# CRIMSON DESERT MODDING TOOLS LICENSE v1.0 (DRAFT)
## A Modified Copyleft License Based on GNU General Public License v3.0

**Copyright (C) 2026 RicePaddySoftware. All Rights Reserved.**

> **STATUS: DRAFT — NOT YET LEGALLY EFFECTIVE.**
> This document is a working draft for review. It is NOT yet the operative license for any RicePaddySoftware project. See "Notes to Reviewer" at the bottom of this file for legal flags that must be resolved before adoption.

---

## 0. PREAMBLE

This License ("CDMTL v1.0") is a derivative work modeled on the GNU General Public License version 3.0 ("GPL v3"). It retains the copyleft principles of GPL v3 — namely, that modifications and redistributions must remain under this same license and that source must be made available — while adding scope restrictions specific to the Crimson Desert modding ecosystem.

**This License is NOT GPL v3 and is NOT compatible with GPL v3, MIT, Apache 2.0, or other OSI-approved licenses.** Code released under those licenses cannot be combined into Covered Work, and Covered Work cannot be relicensed under those terms without permission from RicePaddySoftware.

The intent of this License is to:

1. Permit free use, modification, and redistribution within the Authorized Software Suite.
2. Require that derivative works remain open-source and licensed under these same terms.
3. Prevent unauthorized commercial exploitation of the Field JSON v3.1 / Multi-Target Field Patching specification and its reference implementations.
4. Protect the canonical specifications and trademarks of RicePaddySoftware.
5. Establish enforceable copyright, trademark, and Copyright Management Information (DMCA §1202) protections that platform operators — including NexusMods, ModDB, GitHub, GameBanana, CurseForge, Steam Workshop, and similar mod-distribution services — can rely upon when evaluating takedown notices and trademark complaints concerning the Covered Work.

---

## 1. DEFINITIONS

**"Covered Work"** means the software and specifications licensed under this License, including any derivative works thereof.

**"Authorized Software Suite"** means the following software products, in their current and future versions, developed under the RicePaddySoftware umbrella:

  (a) **DMM** — Definitive Mod Manager (Tauri/Rust desktop application).
  (b) **SWISS Mod Manager** — successor or alternative mod manager developed by RicePaddySoftware.
  (c) **SWISS Save Editor** — Crimson Desert save-game editor.
  (d) **CrimsonGameMods Stacker** — mod creation and stacking tool.
  (e) **dmm-parser** — Rust library and Python bindings for Crimson Desert archive formats.
  (f) **Field JSON v3.1 specification** — and its reference implementations.
  (g) **Any other software** explicitly designated in writing as part of the Authorized Software Suite by RicePaddySoftware.

**"Field JSON Specification"** means the Field JSON v3, v3.1, or any subsequent versioned format authored by RicePaddySoftware for describing field-level modifications to Crimson Desert game archives.

**"Independent Tool"** means software that is NOT part of the Authorized Software Suite and has NOT been granted a written integration license.

**"Licensed Field"** means the field of modding the Crimson Desert video game (developed by Pearl Abyss) and reading, writing, or transforming its archive formats (PAPGT, PAMT, PAZ, PABGB, and successors).

**"You"** means the licensee — any individual or entity exercising rights under this License.

---

## 2. GRANT OF PERMISSIONS

Subject to the conditions and restrictions below, RicePaddySoftware grants You a worldwide, royalty-free, non-exclusive license to:

1. **Use** the Covered Work within the Licensed Field for personal, educational, or research purposes.
2. **Modify** the Covered Work, provided modifications are licensed under this same License.
3. **Redistribute** the Covered Work in source or binary form within the Licensed Field, provided this License accompanies the distribution and all conditions in Section 4 are met.
4. **Fork** the source code for development purposes, provided derivative public distributions remain under this License.

---

## 3. CONDITIONS (COPYLEFT REQUIREMENTS)

All redistributions of the Covered Work, in source or binary form, must:

1. **Retain notices** — all copyright notices, this License text, and any trademark notices in the source.
2. **Provide attribution** — clearly credit "RicePaddySoftware" and link to the canonical repository.
3. **State modifications** — clearly identify any changes made to the Covered Work, with dates.
4. **Disclose source** — when distributing binaries, the corresponding source code (including modifications) must be made available under this License at no charge or via a written offer valid for at least three years.
5. **Preserve license** — derivative works must be licensed under this License in its entirety. No additional restrictions and no relicensing under more permissive terms are allowed.
6. **No endorsement claims** — must not imply endorsement by RicePaddySoftware without prior written permission.

---

## 4. ADDITIONAL RESTRICTIONS (Beyond GPL v3)

The following clauses ADD restrictions beyond GPL v3 and are the reason this License is NOT GPL v3 compatible:

### 4.1 Authorized Suite Requirement

Software that **consumes, produces, parses, generates, or otherwise integrates** the Field JSON Specification for the purpose of modifying Crimson Desert game archives **must** satisfy at least one of the following:

  (a) Be part of the Authorized Software Suite, OR
  (b) Have prior written permission from RicePaddySoftware, OR
  (c) Be a personal-use tool not distributed to other users (single-user, non-public).

### 4.2 No Independent Tool Integration

The Covered Work, including binary or source-form copies of the dmm-parser library, the Field JSON Specification, or reference implementations thereof, may NOT be embedded, statically linked, dynamically linked, vendored, or otherwise integrated into any Independent Tool without a written integration license from RicePaddySoftware.

### 4.3 No Derivative Specifications

You may not publish, distribute, or promote derivative or competing specifications that present themselves as compatible extensions, successors, or replacements for the Field JSON Specification without explicit written designation by RicePaddySoftware. This clause exists to protect the canonical specification from fragmentation.

This restriction does not prohibit:
  - Academic discussion or comparison of the specification.
  - Bug reports, security advisories, or interoperability documentation.
  - Independent specifications targeting different file formats or use cases.

### 4.4 No Commercial Exploitation by Independent Tools

Independent Tools may not commercially distribute, monetize, or sell access to functionality derived from the Covered Work or the Field JSON Specification without a commercial license from RicePaddySoftware.

This restriction does not affect:
  - Sale of unmodified Authorized Software Suite components by RicePaddySoftware.
  - Donations, tips, or voluntary contributions to mod authors using the Authorized Software Suite.
  - Sale of mods (the JSON files themselves) made BY end users, provided no fee is charged for the tools used to create them outside the Authorized Software Suite.

### 4.5 Trademark and Naming

The following are trademarks of RicePaddySoftware:

  - "Field JSON v3.1"
  - "Multi-Target Field Patching"
  - "DMM" / "Definitive Mod Manager"
  - "SWISS" / "SWISS Suite"
  - "RicePaddySoftware"
  - "CrimsonGameMods"

Use of these marks in derivative works, tools, or documentation requires written permission. Compatibility statements ("works with DMM v3.1") are permitted descriptive uses and do NOT require permission.

Use of confusingly similar names — including but not limited to abbreviations, acronyms, transliterations, or stylistic variants of the above marks (such as "DUMM", "CDUMM", "DMM2", "S.W.I.S.S.", "FieldJSON3", "CrimsonModManager", "DefinitiveMM", or any name that combines "Crimson", "Desert", "Definitive", or "SWISS" with mod-management or save-editing terminology) — is prohibited where such use creates a likelihood of confusion in the modding community as to source, sponsorship, or affiliation with RicePaddySoftware.

### 4.6 Copyright Management Information (DMCA §1202)

The Covered Work contains copyright management information ("CMI") within the meaning of 17 U.S.C. § 1202, including:

  (a) The identification of RicePaddySoftware as author and copyright owner.
  (b) The text of this License.
  (c) Trademark notices for "Field JSON v3.1", "DMM", "SWISS", and related marks.
  (d) Per-file copyright headers in source code.
  (e) Version numbers, dates of authorship, and origin URLs (canonical repository links).

**You may not intentionally remove, alter, or falsify any CMI** in the Covered Work, nor distribute the Covered Work knowing that CMI has been removed or altered. Doing so constitutes a separate violation of 17 U.S.C. § 1202 and exposes the violator to statutory damages of $2,500 to $25,000 per violation, plus attorneys' fees, independently of any other remedies under this License.

This clause is intended to be enforced via DMCA takedown notice on any platform hosting unauthorized copies of the Covered Work, including but not limited to mod distribution platforms.

### 4.7 Distribution Platform Restrictions

The Covered Work, in source or binary form, including any modifications or derivative works, **may only be hosted, distributed, mirrored, or made publicly available on the following Authorized Distribution Channels**:

  (a) Repositories under the GitHub organizations or accounts of RicePaddySoftware, including https://github.com/exodiaprivate-eng, https://github.com/NattKh, and any successor accounts officially designated by RicePaddySoftware.
  (b) NexusMods pages owned and operated by RicePaddySoftware or its designated agents.
  (c) The official RicePaddySoftware website (when established) and its associated download CDN.
  (d) Any other distribution channel explicitly authorized in writing by RicePaddySoftware.

**Hosting, mirroring, or redistributing the Covered Work or derivative works on third-party platforms is expressly prohibited without written permission.** Prohibited platforms include, but are not limited to:

  - NexusMods, ModDB, GameBanana, CurseForge, Steam Workshop, ModNexus, Mod.io, and any successor or competitor mod distribution service, when the upload is by anyone other than RicePaddySoftware or an authorized agent.
  - GitHub repositories, GitLab, Bitbucket, Codeberg, or any source-code hosting platform, when the repository is not part of the Authorized Distribution Channels.
  - File-sharing services (MediaFire, Mega, Google Drive, Dropbox, etc.) when used for public redistribution rather than personal backup.
  - Discord servers, Reddit posts, forum attachments, or any chat/social platform when the posting constitutes public redistribution.

This restriction is intended to give RicePaddySoftware a clear basis for issuing takedown notices to platform operators when unauthorized copies are detected.

### 4.8 No Forking for Public Redistribution

While You may create personal forks of the Covered Work for development purposes (per Section 2.4), publishing such forks for public consumption — including making them available on NexusMods, third-party GitHub repositories, or other distribution channels not listed in Section 4.7 — requires prior written authorization from RicePaddySoftware.

This restriction does not affect:
  - Pull requests submitted to the official RicePaddySoftware repositories.
  - Private development forks not shared publicly.
  - Forks created solely for the purpose of submitting bug reports or security advisories.

### 4.9 No Competing Implementation by Licensees

By accepting this License — including by cloning, downloading, building, executing, viewing, reading, indexing, scraping, training upon, or otherwise accessing the Covered Work or the Field JSON Specification documentation, whether directly by Yourself or through an AI assistant, large language model, autonomous coding agent, code-analysis tool, web scraper, search indexer, or any other automated system acting on Your behalf or at Your direction — You agree that, **for a period of three (3) years from the date of Your first such access**, You will not directly or indirectly:

  (a) Develop, publish, or distribute a software tool that performs substantially the same functions as the Authorized Software Suite (i.e., a Crimson Desert mod manager, save editor, or mod-stacking tool) AND that consumes, produces, or interoperates with the Field JSON Specification or any successor format.

  (b) Use knowledge of the Covered Work's internal architecture, methodology, application logic, or mod-mounting/overlay mechanisms — including but not limited to: the runtime injection approach, the field-level patching dispatch system, the typed-table apply mechanism, the PAPGT/PAMT/PAZ rewriting strategy, the trie-based archive lookup, or the multi-target field intent resolution algorithm — to develop a competing tool.

  (c) Reverse engineer the Covered Work, decompile binary distributions, or analyze source code for the purpose of creating a competing implementation, except as expressly permitted by 17 U.S.C. § 1201(f) (interoperability with independently-created programs that do not compete with the Covered Work) or equivalent statutory provisions.

This clause exists because U.S. copyright law (17 U.S.C. § 102(b)) does not extend protection to methods, processes, or systems — only to specific code expression. This License therefore relies on contract law to protect the functional architecture and methodology of the Covered Work against parties who have voluntarily accepted these terms by accessing the Covered Work.

**Permitted Activities** (do not violate this clause):

  1. **Independent prior creation** — Tools that the developer can demonstrate were independently developed without ANY exposure to the Covered Work, the Field JSON Specification, or RicePaddySoftware documentation. The burden of proving independent creation rests with the developer.

  2. **Interoperability without competition** — Tools that read Field JSON v3.1 mod files for archival, conversion, or display purposes, but that DO NOT apply mods to live Crimson Desert game files.

  3. **Academic study and publication** — Research papers, tutorials, blog posts analyzing the Covered Work, provided no competing tool results.

  4. **Contributions to the Authorized Software Suite** — Pull requests, plugins, and extensions accepted into the canonical RicePaddySoftware repositories.

  5. **Expiration** — After the three-year period elapses, this clause no longer restricts the licensee.

**Enforcement:** Violation of this clause constitutes a material breach of this License, terminating all rights under Section 7 and exposing the violator to contract-law remedies including injunctive relief, disgorgement of profits, and damages. RicePaddySoftware may also identify the violator publicly and request that platform operators remove the violating tool on grounds of License breach.

### 4.10 Acceptance by Access (Including AI-Mediated Access)

**Acceptance of this License is triggered by ANY access to the Covered Work**, regardless of the means, duration, or intermediary involved. "Access" includes, but is not limited to:

  (a) Cloning, forking, or downloading any RicePaddySoftware repository.
  (b) Reading source code via the GitHub web interface, GitLab, Sourcegraph, Sourcehut, or any code-browsing service.
  (c) Downloading binary releases, installers, or packaged distributions.
  (d) Reading the Field JSON Specification document, README files, or related documentation.
  (e) Executing the Covered Work or any binary built from it.
  (f) Inspecting compiled binaries via decompilation, disassembly, static analysis, or dynamic analysis tools.
  (g) Reading the Covered Work via web archives (Wayback Machine, archive.today, Google Cache, GitHub Archive Program) or any successor archival service.
  (h) Receiving or viewing copies distributed by third parties, regardless of whether such distribution was authorized.

#### 4.10.1 Acceptance via AI Assistants and Automated Agents

Access to the Covered Work via an AI assistant, large language model (LLM), code-analysis agent, autonomous coding tool, web scraper, search engine indexer, retrieval-augmented-generation (RAG) system, or any other automated system acting on Your behalf or at Your direction **constitutes Your acceptance of this License**. You cannot escape the obligations of this License by interposing an AI, agent, or other automated intermediary between Yourself and the Covered Work.

This includes, but is not limited to:

  (a) Prompting an AI assistant — such as Claude (Anthropic), ChatGPT (OpenAI), Gemini (Google), Cursor, GitHub Copilot, Sourcegraph Cody, Aider, Cline, Devin, Windsurf, Replit Agent, or any present or future AI coding tool — to read, summarize, analyze, refactor, translate, port, or replicate the Covered Work.
  (b) Using an autonomous coding agent or AI-driven development environment to clone, decompile, parse, or process RicePaddySoftware repositories, binaries, or documentation.
  (c) Using a web-scraping service, code-indexing service, or AI training pipeline to retrieve the Covered Work for analysis or model training.
  (d) Receiving AI-generated explanations, summaries, pseudocode, architectural diagrams, or refactored code derived from the Covered Work.
  (e) Using AI-generated code that incorporates, paraphrases, structurally mirrors, or is derived from the Covered Work, regardless of whether You personally observed the source code from which it was derived.
  (f) Asking an AI to "build a tool similar to DMM" or "implement a Crimson Desert mod manager" if the AI's response is informed (whether at training time or inference time) by the Covered Work.

#### 4.10.2 No AI Training Without Authorization

The Covered Work may not be used as training data, fine-tuning data, retrieval-augmented-generation (RAG) source material, in-context-learning examples, or any other form of input to an AI model, agent, or automated system intended to:

  (a) Generate competing implementations of the Authorized Software Suite (per Section 4.9).
  (b) Extract or replicate the methodology, architecture, or application logic of the Covered Work (per Section 4.9).
  (c) Produce derivative documentation of the Field JSON Specification without attribution to RicePaddySoftware.
  (d) Generate code, documentation, or analysis that would, if produced by a human licensee, violate any other clause of this License.

Use of the Covered Work as input to AI tools for purposes consistent with the Authorized Software Suite ecosystem (e.g., a Claude-assisted developer working on a RicePaddySoftware-approved contribution to DMM) is permitted, provided such use complies with all other clauses of this License.

#### 4.10.3 Imputation of Knowledge

Knowledge, methodology, architecture, application logic, or implementation details extracted from the Covered Work via AI assistants, automated agents, or any other intermediary tool **are imputed to You** — the human user who directed, prompted, or otherwise caused the access — for purposes of Section 4.9 (No Competing Implementation by Licensees).

You cannot claim "the AI read it, not me" as a defense to building a competing tool. Under principles of agency law, an automated system acting on Your behalf is legally equivalent to Your own action for purposes of License acceptance and breach analysis.

#### 4.10.4 Reasonable Notice

This License is published prominently:

  (a) As `LICENSE.txt` (or equivalent) at the root of every RicePaddySoftware repository.
  (b) As a copyright header at the top of every source file in the Covered Work.
  (c) In the README of every RicePaddySoftware repository.
  (d) On the NexusMods page (and other Authorized Distribution Channels) for every distributed binary.
  (e) At the canonical URL https://github.com/exodiaprivate-eng/dmm-parser/blob/main/LICENSE.txt (or successor URL designated by RicePaddySoftware).

By accessing the Covered Work through any of these channels — or any unauthorized copy that retains the original notices — You acknowledge constructive notice of these terms. Stripping these notices does not eliminate Your obligations under this License; it instead constitutes an additional violation under Section 4.6 (Copyright Management Information / DMCA §1202).

---

## 5. PERMITTED EXCEPTIONS

The following uses are explicitly permitted without separate authorization, even where Sections 4.1–4.4 would otherwise restrict them:

1. **Personal use** — A single individual using a personal tool for their own gameplay, with no public distribution.
2. **Educational use** — Academic study, classroom instruction, and research on the file formats and specifications.
3. **Security research** — Vulnerability discovery, responsible disclosure, and defensive security analysis.
4. **Interoperability with non-CD tooling** — Translation FROM Field JSON Specification TO unrelated archival or interchange formats, where the destination is NOT used to modify Crimson Desert game archives.
5. **Bug reports and feedback** — Submission of issues, pull requests, and constructive criticism.
6. **Reverse engineering for compatibility** — As required and permitted by applicable copyright law (e.g., 17 U.S.C. § 1201(f) in the United States, equivalent EU directives, etc.).

---

## 6. CONTRIBUTIONS

Contributions submitted to RicePaddySoftware repositories are governed by a separate Contributor License Agreement (CLA) [TO BE DRAFTED]. By submitting a contribution, You agree to license it under this License and grant RicePaddySoftware the right to relicense future versions if needed.

If no CLA is in place at the time of contribution, the contribution is presumed to be licensed under CDMTL v1.0 with the right of RicePaddySoftware to incorporate it into the Authorized Software Suite.

---

## 7. TERMINATION

Your rights under this License terminate automatically if You materially violate any of its terms.

You may regain Your rights by:

1. Ceasing the violating activity within thirty (30) days of receiving written notice, AND
2. Either curing the violation OR receiving written reinstatement from RicePaddySoftware.

Termination does not affect:
  - The rights of downstream end users who received copies of the Covered Work in compliance with this License before Your termination.
  - The validity of mods created by end users using compliant Authorized Software Suite tools.

---

## 8. ENFORCEMENT MECHANISM

RicePaddySoftware reserves all rights and remedies available under applicable copyright, trademark, and contract law to enforce this License. Without limiting the foregoing, RicePaddySoftware specifically intends to enforce violations through the following mechanisms:

### 8.1 DMCA Takedown Notices

For unauthorized hosting or distribution of the Covered Work on third-party platforms (including but not limited to NexusMods, ModDB, GameBanana, GitHub, GitLab, CurseForge, Steam Workshop, Mod.io, and similar services), RicePaddySoftware will issue takedown notices under 17 U.S.C. § 512 (Digital Millennium Copyright Act) directly to the platform operator. By accepting this License, You acknowledge that:

  (a) Hosting or redistributing the Covered Work outside the Authorized Distribution Channels (Section 4.7) constitutes copyright infringement actionable under DMCA.
  (b) Removing or altering Copyright Management Information (Section 4.6) is independently actionable under 17 U.S.C. § 1202 with statutory damages of $2,500 to $25,000 per violation.
  (c) Platform operators are entitled to rely on RicePaddySoftware's good-faith DMCA notices in removing infringing content.

### 8.2 Trademark Enforcement

For unauthorized use of RicePaddySoftware trademarks (Section 4.5), including confusingly similar names targeting the Crimson Desert modding community, RicePaddySoftware will pursue:

  (a) Trademark complaints to the hosting platform under its trademark policy.
  (b) UDRP (Uniform Domain-Name Dispute-Resolution Policy) proceedings for domain-name infringement.
  (c) Cease-and-desist letters and trademark infringement litigation under the Lanham Act (15 U.S.C. § 1051 et seq.) or equivalent foreign trademark law.

### 8.3 License Violation Remedies

For violations of License terms not otherwise covered by copyright or trademark enforcement (e.g., breach of the Authorized Suite Requirement in Section 4.1), RicePaddySoftware reserves the right to:

  (a) Terminate the violator's License grant under Section 7.
  (b) Pursue contract-law remedies, including specific performance and damages.
  (c) Seek injunctive relief to prevent ongoing violations.
  (d) Publicly identify violators and excluded forks via official RicePaddySoftware communication channels.

### 8.4 No Waiver

Failure of RicePaddySoftware to enforce any provision of this License at any time shall not be construed as a waiver of the right to enforce that provision later. Selective enforcement does not create a defense or estoppel for any violator.

### 8.5 Cooperation with Platform Operators

This License is intended to be self-executing for the purposes of platform-mediated enforcement. RicePaddySoftware grants platform operators (NexusMods, ModDB, GitHub, etc.) the right to rely on this License text as a basis for evaluating takedown requests, DMCA notices, and trademark complaints concerning the Covered Work.

---

## 9. WARRANTY DISCLAIMER

THE COVERED WORK IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NONINFRINGEMENT, AND TITLE.

IN NO EVENT SHALL RICEPADDYSOFTWARE OR ANY CONTRIBUTOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THE COVERED WORK, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

---

## 10. RELATIONSHIP TO THE GAME

The Covered Work is a third-party modding toolkit. It is **not** affiliated with, endorsed by, or sponsored by Pearl Abyss, the developers of Crimson Desert, or any related entity. End users assume all responsibility for compliance with the game's End User License Agreement and applicable laws when using the Covered Work to modify game files.

---

## 11. JURISDICTION AND DISPUTE RESOLUTION

This License shall be governed by and construed in accordance with the laws of **[JURISDICTION TO BE DETERMINED — typically the country/state where RicePaddySoftware is incorporated]**, without regard to conflict-of-laws principles.

Any dispute arising out of or relating to this License shall be resolved by **[binding arbitration / courts of competent jurisdiction in JURISDICTION — to be decided]**.

---

## 12. ACKNOWLEDGMENT

By using, modifying, distributing, accessing, reading, viewing, downloading, executing, or otherwise interacting with the Covered Work — whether directly by Yourself or through an AI assistant, automated agent, code-analysis tool, web scraper, or any other intermediary acting on Your behalf or at Your direction — You acknowledge that You have read (or had constructive notice of) this License, understand its terms, and agree to be bound by them. If You do not agree to these terms, You must not access, use, or direct any agent (human or automated) to access or use the Covered Work.

---

## 13. SEVERABILITY

If any provision of this License is found unenforceable in any jurisdiction, the remaining provisions shall continue in full force and effect, and the unenforceable provision shall be interpreted to most closely match the original intent in a manner that is enforceable.

---

# NOTES TO REVIEWER (Not Part of the License)

These are concerns and open questions you should resolve **before** adopting this license. I am not a lawyer; this draft is a starting point, not legal advice. **Consult a software licensing attorney before publishing.**

## Critical Legal Realities

1. **You cannot call this "GPL v3" or "GNU GPL"** — those names are protected. The FSF's GPL v3 expressly forbids modification and renaming. The most you can say is "modeled on" or "based on the structure of" GPL v3. I named this draft "CDMTL v1.0" (Crimson Desert Modding Tools License) instead.

2. **This is NOT open source by OSI definition.** The Open Source Initiative will not certify any license that restricts who can use software or for what purpose. You will be operating in "source-available" / "shared-source" territory — closer to BUSL (Business Source License) or Elastic License v2 than GPL.

3. **License incompatibility is bidirectional.** Once you adopt CDMTL:
   - You cannot pull in code from MIT/Apache/GPL projects without violating their terms (their licenses don't allow your additional restrictions).
   - GPL/MIT/Apache projects cannot pull from your code.
   - This includes most Rust crates on crates.io (most are MIT/Apache-2.0 dual licensed).
   - **dmm-parser currently uses PyO3 (Apache-2.0/MIT)** — this is OK because Apache/MIT permit redistribution under more restrictive licenses for compiled output. But any AGPL or LGPL dependency would be a hard block.

4. **Existing GPL'd or MIT'd contributions cannot be retroactively relicensed.** If anyone has contributed code to dmm-parser, DMM, or CrimsonGameMods under their existing license, you need their explicit consent to relicense under CDMTL. Without a CLA in place from day 1, you have a relicensing problem.

5. **"RicePaddySoftware" must be a real legal entity** for many of these clauses to be enforceable in court. If it's currently just a name you're using, register it (LLC, sole proprietorship, etc.) before publishing the license.

6. **Trademark protection requires registration** — claiming "Field JSON v3.1™" only has bite if you've actually filed a trademark in your jurisdiction. Until then, you have common-law trademark rights at best, which are weak.

## Open Drafting Questions

I left **[BRACKETED PLACEHOLDERS]** in the draft. You need to decide:

1. **Jurisdiction (Section 10)** — Where are you incorporated / where do you live? US state, UK, EU country, etc. This determines which laws apply.

2. **Dispute resolution** — Arbitration (cheaper, private, harder to appeal) vs. courts (public, slower, more expensive).

3. **Contributor License Agreement** — Section 6 references a CLA that doesn't exist yet. Do you want one? (Highly recommended for any project accepting outside PRs.)

4. **Patent grant clause** — GPL v3 has an explicit patent grant. I omitted it from this draft because it's complex; we should add one if you want patent protection.

5. **"Future versions" auto-upgrade** — GPL v3 has language allowing licensees to choose any future version. Do you want CDMTL v2 to automatically apply, or should each version stand alone?

6. **End-user-game-modification disclaimer (Section 9)** — Pearl Abyss' EULA might forbid modding entirely. Section 9 disclaims your responsibility, but you may want stronger language.

## Things I Did NOT Address

- **GDPR / privacy** — if any tool collects user data, separate privacy policy needed.
- **Export controls** — cryptography in dmm-parser (ChaCha20) may trigger US export controls or equivalent.
- **DMCA takedown response** — if Pearl Abyss tries to take down the tools, what's your response plan?
- **Sub-licensing structure** — can you license CDMTL components to a partner separately? Currently no, intentionally.

## Recommended Next Steps

1. Review the draft and tell me which clauses to tighten, loosen, or remove.
2. Decide jurisdiction so I can fill in Section 10.
3. Decide whether to retain or remove Section 4.4 (commercial exploitation) — this is the harshest clause and may discourage community contributions.
4. Consider whether to add a "free for non-commercial Crimson Desert mod authors" carve-out — this would let independent modders use SWISS-derived code in their own personal mod tools.
5. Get this in front of an actual licensing attorney before publishing. Cost: typically $500–$2,000 USD for a license review by a software-IP-focused lawyer. Worth it.

---

*End of Draft.*
