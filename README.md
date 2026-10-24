# ScamIntel — email-phish-takedown 2.4.0

Defensive email-phishing intelligence and evidence collector.

Evidence-handling tool first, IOC analyzer second. Built for one job:
take a phishing message in, preserve it like evidence, analyze a copy,
and produce a case directory a registrar, host, or investigator can act
on — with a chain of custody that survives scrutiny.

## What it does

**Phase A — Acquisition (immutable)**
- Pulls raw Gmail API response bytes; the SHA-256 of the raw bytes is
  the primary evidence hash. The raw message is never re-serialized
  for hashing; analysis parses a copy.
- Write-once artifacts: a collision raises instead of overwriting.
- Crash-safe writes: temp file + fsync + atomic rename.

**Phase B — Analysis (derived, never mutates evidence)**
- IOC extraction, static HTML/JS redirect analysis, URL scoring,
  header/authentication analysis, attachment hashing.
- Optional validated network collection (`--network`, OFF by default):
  manual redirect tracing, per-hop SSRF validation, TLS inspection,
  DNS.
- **Device-code phishing check (new in this release):** a static,
  heuristic check for the OAuth device authorization grant abuse
  pattern — an attacker-supplied code plus a device-login endpoint
  plus entry instructions. Scores are labeled heuristic, and the flag
  names the *pattern* only. It never attributes a message to a
  specific kit, actor, or campaign, because the pattern alone cannot
  prove that.
- Abuse-report drafts for registrars/hosts, defanged, human review
  required. Nothing is submitted anywhere automatically.

**Integrity**
- `manifest.json`: tamper-evident artifact manifest with full lineage
  per artifact; its hash is anchored in `case.json`.
- `audit.json`: chain-of-custody event trail, written even on failure.
- Standalone verification: `verify --case-dir <dir>` reports
  PASS / MISMATCH / MISSING / UNEXPECTED.

## Usage

```text
# Build a case from a Gmail message
email-phish-takedown-2.4.0.py collect --message-id <id> --slug <case-slug>

# Verify a case directory
email-phish-takedown-2.4.0.py verify --case-dir <case-dir>
```

Network collection is opt-in (`--network`) and off by default.
Private/non-public destinations are blocked by default. No credential
submission, no JavaScript execution, no browser automation.

## 2.4.0 validation

- The device-code check was validated two ways: a 44-check proof
  suite (fires on device-code lures, silent on ordinary phish, silent
  on solicited brand-sent sign-in codes, gate blocks a lone legitimate
  device-login link), and an adversarial bench of 72 synthetic,
  defanged fixtures across four mutation rounds (see
  `docs/VALIDATION-REPORT-device-code.md`).
- Evidence-integrity behavior is unchanged from the 2.4.0 hardening
  pass: verify output on existing 2.4.0 case directories is
  byte-identical under this build.

## Related

- [phish-kit-fingerprints](https://github.com/mjk72578/phish-kit-fingerprints) — fingerprints and tooling from phishing-kit takedown analysis
- [qr-kit-fingerprint](https://github.com/mjk72578/qr-kit-fingerprint) — QR-code phishing kit fingerprinting

Defensive research only. Lures referenced in validation material are
synthetic and defanged; no live phishing infrastructure is touched.
