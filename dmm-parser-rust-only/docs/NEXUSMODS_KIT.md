# NexusMods Enforcement Kit

The minimum viable kit for getting unauthorized copies removed from NexusMods. Cut down from the full enforcement playbook — this is the operational stuff only.

---

## The Honest Reality

**NexusMods staff will NOT read your license.** They will not evaluate clauses. They handle DMCA notices and trademark complaints based on **clear evidence**, nothing else.

So your license is mostly irrelevant to the takedown decision. What matters:

1. **Authorship proof** — can you show you made it first?
2. **Clear copying** — can you show their upload matches yours?
3. **A clean DMCA notice** — properly formatted, all elements present?

That's it. The license you wrote, the per-file headers, the §4.9/§4.10 clauses — those come into play only if you sue (which you said you won't). For NexusMods, it's: **prove you made it, prove they copied it, send a proper DMCA.**

---

## Three Things You Need (in priority order)

### 1. Public "Authorized Channels" notice (DONE — in your READMEs)

Without this, NexusMods staff have no way to verify "this upload is unauthorized." With it, you have a clean basis for every takedown: "It's not on the authorized channels list."

This is now in:
- `dmm-parser/README.MD`
- `dmm-api-test/README.md` (DMM-BETA)
- `CRIMSON-DESERT-SAVE-EDITOR-AND-GAME-MODS-clone/README.md` (SWISS)

When you publish DMM on NexusMods, **paste the same Authorized Channels notice into the mod page description**. That's where NexusMods staff will look first when evaluating a complaint.

### 2. Trademark filing for "DMM" or "Definitive Mod Manager" — $250–350, do this NOW

This is the single highest-leverage action. With a registered ® on "DMM" or "Definitive Mod Manager":

- Any tool calling itself "CDUMM" / "DUMM" / "DMM2" is a trademark complaint, not a copyright claim
- NexusMods has a separate trademark complaint process that's faster than DMCA
- You don't need to prove copying — just the confusing similarity
- Statutory damages start at $1,000 per counterfeit good

**How:**
1. Go to https://www.uspto.gov/trademarks/apply
2. Use TEAS Plus ($250) — cheapest option
3. File for: "Definitive Mod Manager" in **Class 9** (Computer software)
4. Description: "Computer software for installing, managing, and applying modifications to video games"
5. Specimen: screenshot of DMM running with the name visible
6. Wait 6–12 months for registration. **TM symbol can be used immediately**, ® only after registration.

**If you want to spread the budget:**
- Priority 1: "Definitive Mod Manager" — $250 (1 mark, Class 9)
- Priority 2: "Field JSON v3.1" — could be tricky (descriptive marks get rejected)
- Priority 3: "SWISS Suite" — $250 (1 mark, Class 9)

Total recommended: $500 covers the two most useful marks.

### 3. Pre-filled DMCA template (BELOW — copy/paste/fire when needed)

You don't have time to write a DMCA from scratch when you find a violation. Have it ready to send.

---

## DMCA Template (Copy/Paste Ready)

**Send to:** `dmca@nexusmods.com`

**Subject line:** `DMCA Takedown Notice — Unauthorized Copy of [TOOL NAME] — [INFRINGING URL or USERNAME]`

**Body:**

```
To: NexusMods DMCA Agent

I am the copyright owner of [TOOL NAME], distributed by RicePaddySoftware
under the Crimson Desert Modding Tools License v1.0 (CDMTL v1.0).

This notice complies with the Digital Millennium Copyright Act
17 U.S.C. § 512(c)(3).

1. IDENTIFICATION OF COPYRIGHTED WORK:
   Tool: [DMM / SWISS Save Editor / dmm-parser / etc.]
   Original distribution URL: https://github.com/exodiaprivate-eng/[REPO]
   First publication date: [GIT FIRST COMMIT DATE]
   License: CDMTL v1.0 — https://github.com/exodiaprivate-eng/[REPO]/blob/main/LICENSE.txt
   [Include if registered:] US Copyright Registration: TX-[NUMBER]

2. IDENTIFICATION OF INFRINGING MATERIAL:
   URL: [FULL NEXUSMODS URL]
   Mod name: [as displayed on the page]
   Uploader username: [their NexusMods username]
   Date uploaded: [date from the page]

3. EVIDENCE OF INFRINGEMENT:
   [Pick the strongest one or two — do not list all unless they all apply]

   (a) Direct binary copy. SHA-256 of my official release [VERSION]:
       [HASH]
       SHA-256 of their uploaded file (downloaded [DATE]):
       [HASH]
       The hashes match — this is a verbatim redistribution of my software
       without authorization.

   (b) Source code copying. The uploaded archive contains source files
       directly copied from my repository, including [SPECIFIC FILES].
       Side-by-side comparison attached.

   (c) Stripped Copyright Management Information. The uploaded copy has
       had the per-file copyright headers (which were present in my
       original distribution) removed or altered. This independently
       violates 17 U.S.C. § 1202.

   (d) Distribution outside Authorized Channels. My software is
       distributed exclusively through the authorized channels listed
       at https://github.com/exodiaprivate-eng/[REPO]#license--authorized-distribution.
       This NexusMods upload is by an unauthorized party and is not part
       of those channels.

4. GOOD FAITH STATEMENT:
   I have a good faith belief that use of the material in the manner
   complained of is not authorized by the copyright owner, its agent,
   or the law.

5. ACCURACY STATEMENT:
   The information in this notification is accurate, and under penalty
   of perjury, I am authorized to act on behalf of the copyright owner
   of the exclusive right that is allegedly infringed.

6. CONTACT INFORMATION (required by 17 U.S.C. § 512(c)(3)(A)(iv)):
   Name: [YOUR LEGAL NAME]
   Affiliation: RicePaddySoftware (Copyright Owner)
   Email: [YOUR EMAIL]
   Postal address: [YOUR PHYSICAL ADDRESS — DMCA REQUIRES THIS]
   Phone: [YOUR PHONE — DMCA REQUIRES THIS]

7. SIGNATURE:
   /s/ [YOUR NAME]
   Date: [TODAY'S DATE]

ATTACHMENTS:
- Screenshot of infringing NexusMods page (saved with timestamp)
- SHA-256 of original release: [from your records]
- SHA-256 of downloaded infringing file
- Side-by-side comparison of any code or assets, if applicable
- Link to original LICENSE.txt establishing CDMTL v1.0 terms
```

### What goes in the placeholders

Before you ever need this, fill in your fixed info ONCE:

```
[YOUR LEGAL NAME] = [fill in]
[YOUR EMAIL] = [fill in]
[YOUR PHYSICAL ADDRESS] = [fill in — DMCA REQUIRES this]
[YOUR PHONE] = [fill in — DMCA REQUIRES this]
```

**Keep this somewhere safe.** A DMCA without contact information will be rejected.

---

## Trademark Complaint Template (Different Process)

For "CDUMM" / "DUMM" / "DMM2" / similar-name copies, file a TRADEMARK complaint, not a DMCA.

**Send to:** `legal@nexusmods.com` (NOT `dmca@`)

**Subject:** `Trademark Complaint — Unauthorized use of "[YOUR MARK]" — [INFRINGING URL]`

**Body:**

```
To: NexusMods Legal Team

I am writing on behalf of RicePaddySoftware regarding unauthorized
use of our trademark on a NexusMods upload.

1. TRADEMARK INFORMATION:
   Mark: [DMM / Definitive Mod Manager / Field JSON v3.1 / etc.]
   Owner: RicePaddySoftware
   Registration status: [USPTO Reg. No. XXXXXXX / Pending application Serial No. XXXXXXX / Common-law trademark since FIRST USE DATE]
   Use in commerce: Computer software for Crimson Desert game modification
   Class: 9 (Computer software)

2. INFRINGING USE:
   URL: [FULL NEXUSMODS URL]
   Mod name: [as displayed]
   Uploader: [username]
   Manner of infringement:
   - The uploader names their tool "[INFRINGING NAME]" which is
     confusingly similar to our registered mark "[YOUR MARK]"
   - This creates likelihood of confusion in the Crimson Desert
     modding community as to the source, sponsorship, or affiliation
     of the upload
   - The infringing tool targets the same user base (Crimson Desert
     mod users) and serves the same function (mod management /
     [whatever])
   - Our trademark predates this upload by [TIMEFRAME]

3. RELIEF REQUESTED:
   Removal of the infringing upload, or at minimum, requirement that
   the uploader rename their tool to remove the confusingly similar
   mark.

4. CONTACT:
   Name: [YOUR NAME]
   Affiliation: RicePaddySoftware
   Email: [YOUR EMAIL]
   Phone: [YOUR PHONE]

ATTACHMENTS:
- Screenshot of infringing page
- Evidence of trademark registration (USPTO TSDR printout) or
  evidence of first use in commerce (early commits, blog posts,
  Discord announcements with timestamps)
- Side-by-side comparison of the marks
```

---

## Evidence Collection (5 minutes, do every release)

When you ship a new version of DMM / SWISS / dmm-parser, automate this:

```bash
# After every release:
sha256sum dist/dmm-installer.exe > releases/dmm-v1.2.3.sha256
git tag -a v1.2.3 -m "Release v1.2.3"
git push origin v1.2.3

# Save these in a spreadsheet:
# - Version
# - Release date
# - SHA-256 hash
# - GitHub Release URL
# - NexusMods upload URL
```

When a violation appears, you can immediately point to:
- "I released v1.2.3 on [DATE] with SHA-256 [HASH]"
- "Their upload SHA-256 is [HASH] — matches mine"

This kind of clean evidence makes NexusMods takedowns nearly automatic.

---

## What NexusMods Will and Will Not Honor

### WILL honor (high success rate)

- Direct binary/source copying with SHA-256 evidence
- Stripped copyright headers (§1202 angle)
- Trademark infringement (especially with registered ®)
- Confusingly similar names that target your user base
- Third-party reuploads of your binaries
- Stolen assets/icons/screenshots from your tool

### WILL NOT honor (skip these claims)

- "They violated my license clauses 4.9/4.10"
- "They reverse-engineered my tool"
- "They consume my JSON format"
- "Their architecture is similar to mine"
- "They built a competing tool"

If your evidence boils down to "I think they used AI to read my code," NexusMods will pass and tell you to file in court. Save those arguments for situations where you have actual code/string matches.

---

## When You're Ready to Publish DMM on NexusMods

Drop this exact text into the mod page description (right after the basic description):

```markdown
## License & Authorized Distribution

DMM is licensed under CDMTL v1.0 (https://github.com/exodiaprivate-eng/Definitive-Mod-Manager/blob/main/LICENSE.txt).

This is the ONLY authorized NexusMods upload of DMM, by the official
author RicePaddySoftware. Any other NexusMods upload of DMM, or any
similarly-named tool ("CDUMM", "DUMM", "DMM2", etc.) is unauthorized
and a trademark/copyright violation.

If you find an unauthorized copy on NexusMods, please report it via
the "Report Mod" button.
```

This single paragraph gives NexusMods staff what they need to evaluate any future complaint instantly.

---

## TL;DR — The Three Things That Matter

1. **Authorized Channels notice in README + NexusMods page** — DONE
2. **Trademark registration** ($250–500, 6–12 months wait) — DO THIS WEEK
3. **DMCA template + filled-in contact info ready to fire** — KEEP THIS DOC HANDY

That's it. Everything else is bonus.
