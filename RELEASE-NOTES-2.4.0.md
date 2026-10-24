# ScamIntel 2.4.0 — release notes

Released 2026-10-23.

## Headline: device-code phishing detection, merged in

This release merges the device-code phishing check into the main tool
(it was developed and validated as a dev build, then merged for
release rather than published as a separate module, so there is one
codepath to maintain).

The check recognizes the OAuth device authorization grant abuse
pattern that defines the 2026 kit wave: the lure's link is the
*genuine* provider device-login page, so there is no bad URL to catch —
the attack is the attacker-supplied code and the instructions to enter
it. The check weighs the context together: legitimate or lookalike
device-login endpoint, attacker-supplied code, entry instructions,
brand-vs-sender mismatch, QR-instruction body, pretext, short-fuse
urgency. A gate requires an endpoint-or-QR anchor plus corroborating
context, so a lone legitimate device-login link cannot fire it, and a
solicited-context suppression keeps genuine brand-sent sign-in codes
silent.

Every score is labeled **heuristic**. A flag reads "Consistent with
device-code grant abuse pattern" — pattern only, never a kit or actor
attribution.

Results land in `analysis/device-code.json`, a `case.json` summary
block, a report section, and the audit trail. SCHEMA_VERSION 6 → 7 for
the new artifact and metadata fields.

## Validation

- Proof suite: 44/44 checks — 7/7 lure classes fire (direct code+link,
  QR minimal body, IT-pretext lookalike sender, code in subject,
  shortlink endpoint, meeting-verification pretext, lookalike
  endpoint); 3/3 ordinary phish silent; benign solicited sign-in
  silent; lone legitimate link gate-blocked.
- Adversarial bench: 72 synthetic defanged fixtures, 4 rounds
  (canonical + 3 mutation rounds). Final module catch rate 100% per
  attack class, 0/7 false positives on benign controls. Three breaks
  found and hardened during the bench (split subject/body code
  reassembly, QR-construction verdict weight, awareness-context cap).
  Full report: `docs/VALIDATION-REPORT-device-code.md`.
- Integrity: this build's `verify` output on an existing 2.4.0 case
  directory is byte-identical to 2.4.0's own (19 PASS, 0 mismatch).
  Hashing, manifest, audit, and verify code are unchanged.

## Also in 2.4.0 (the hardening pass)

- Write-once race fixed: publish via `os.link()`; symlink destinations
  rejected; directory fsync.
- `--slug` restricted to `[A-Za-z0-9_-]{1,64}`; case directory verified
  to stay inside the output root.
- Verifier rejects duplicate artifact paths and validates artifact
  record schema.
- Fake-CAPTCHA lure detection (companion module, static analysis only).

## Known limits

- The device-code check cannot see text inside attachment file
  contents (no static check in this tool extracts attachment text);
  QR-carried lures are caught on construction and context indicators.
- The bench was authored by the same hand as the module; it is
  regression-grade validation, not independent verification.
- Codes are recognized in 8–10 character mixed alphanumeric shapes;
  exotic code formats may score below the flag line and land in the
  human-review tier instead.
