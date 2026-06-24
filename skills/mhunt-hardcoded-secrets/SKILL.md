---
name: mhunt-hardcoded-secrets
description: Mobile hunting skill for hardcoded secrets (code) on Android/iOS apps. Ported from droid-llm-hunter vuln_rule 'hardcoded_secrets'. MASVS-STORAGE-2 (Hardcoded Secrets Detection). Use when /hunt-mobile (via mhunt-dispatch) fires this rule's detection_pattern, or when hunting hardcoded secrets (code) in a decompiled app.
source: droid-llm-hunter (config/prompts/vuln_rules/hardcoded_secrets.yaml)
masvs: MASVS-STORAGE-2
---

# mhunt-hardcoded-secrets

port of droid-llm-hunter's `hardcoded_secrets` vuln_rule into the `/hunt-mobile` model. **Hardcoded Secrets (code)** — API keys, credentials, or encryption keys baked into source/Smali. Anyone who unzips the APK/IPA recovers them.

## MASVS

`MASVS-STORAGE-2` — Hardcoded Secrets Detection. likely severity: **Medium** (confirm via the Gate-0 below; mobile severity depends on reachability + impact, not the pattern alone).

## Detection signal (the rule's `detection_pattern`)

android (smali/java/xml) — grep verbatim:

```
(?i)(AIza[0-9A-Za-z-_]{35}|AKIA[0-9A-Z]{16}|const-string.*(api_key|password|secret|token)|(api_key|password|secret|token).*=.*[\"'])
```

ios parallel: API keys / tokens in the Mach-O `strings` output, `Info.plist`, or embedded config; `kSecAttr` keys hardcoded

a regex hit is a **lead, not a finding** — droid-llm-hunter then deep-scans it with the LLM. that deep-scan is the methodology below.

## Static methodology (deep scan)

- Grep for vendor key shapes (`AIza...` Google, `AKIA...` AWS, `sk_live_` Stripe, `xox` Slack) and assignment patterns (`secret =`, `password =`, `const-string` to a secret-named field).
- Triage entropy: distinguish real keys from placeholders/UI strings.
- Verify the key is live before reporting (test against the vendor API, read-only) — a dead key is informational.

## Dynamic confirmation

- `strings classes.dex`/`strings <macho>` and `grep -Ri 'api[_-]?key\|secret\|token'` across decompiled tree + assets.

device prereqs: rooted Android emulator/device with `adb` + `frida-server` (and `drozer`/`objection` where noted), or a jailbroken iOS device with `frida`/`objection`. no device -> report as a static-only lead, don't claim confirmed.

## PoC

```bash
# pull and scan
grep -rEn 'AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{24}' jadx/ raw/assets/
# validate (example: Google Maps key) -> if it returns data, key is live
curl -s "https://maps.googleapis.com/maps/api/geocode/json?address=x&key=$KEY"
```

## Validation — MASVS Gate-0

before writing the report, answer all three:

1. **Reachability** — can an *external* actor trigger this (another app, a deep link, a network response, a shared file), or only the app itself? app-internal-only is usually not a finding.
2. **Impact** — what does the attacker gain (data read/write, code execution, auth bypass, privilege gain) and which CIA property does the victim lose? map to `MASVS-STORAGE-2`.
3. **Reproducible in 10 min** — exact entry point (component/URI/intent) + payload + observed result (leaked data / state change / execution), on a clean install, no pre-seeded state.

if any answer is weak, it's a static lead — keep hunting, don't file.

## Chains

live cloud key -> `cloud-iam-deep` / backend access; cross-ref `mhunt-hardcoded-secrets-xml` for the strings.xml variant.
