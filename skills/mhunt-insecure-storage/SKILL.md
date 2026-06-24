---
name: mhunt-insecure-storage
description: Mobile hunting skill for insecure data storage on Android/iOS apps. Ported from droid-llm-hunter vuln_rule 'insecure_storage'. MASVS-STORAGE-1 (Insecure Data Storage). Use when /hunt-mobile (via mhunt-dispatch) fires this rule's detection_pattern, or when hunting insecure data storage in a decompiled app.
source: droid-llm-hunter (config/prompts/vuln_rules/insecure_storage.yaml)
masvs: MASVS-STORAGE-1
---

# mhunt-insecure-storage

port of droid-llm-hunter's `insecure_storage` vuln_rule into the `/hunt-mobile` model. **Insecure Data Storage** — Sensitive data written to SharedPreferences/plist/files in cleartext, or with world-readable/writable modes, where other apps or a backup can read it.

## MASVS

`MASVS-STORAGE-1` — Insecure Data Storage. likely severity: **Medium** (confirm via the Gate-0 below; mobile severity depends on reachability + impact, not the pattern alone).

## Detection signal (the rule's `detection_pattern`)

android (smali/java/xml) — grep verbatim:

```
(?i)(SharedPreferences|getSharedPreferences|openFileOutput|MODE_WORLD_READABLE|MODE_WORLD_WRITABLE)
```

ios parallel: secrets in `NSUserDefaults`/plist instead of Keychain; `kSecAttrAccessibleAlways`; unencrypted Core Data / sqlite

a regex hit is a **lead, not a finding** — droid-llm-hunter then deep-scans it with the LLM. that deep-scan is the methodology below.

## Static methodology (deep scan)

- Find `getSharedPreferences`/`openFileOutput` storing tokens, passwords, PII; check the value isn't encrypted (no Keystore/EncryptedSharedPreferences).
- Flag any `MODE_WORLD_READABLE`/`MODE_WORLD_WRITABLE` (deprecated, cross-app exposure).
- Check `android:allowBackup="true"` — secrets then exfil via `adb backup` without root.

## Dynamic confirmation

- On a rooted device/emulator: `adb shell run-as com.target cat /data/data/com.target/shared_prefs/*.xml`.
- `objection`: `android keystore list`, `android hooking search` for SharedPreferences writes.

device prereqs: rooted Android emulator/device with `adb` + `frida-server` (and `drozer`/`objection` where noted), or a jailbroken iOS device with `frida`/`objection`. no device -> report as a static-only lead, don't claim confirmed.

## PoC

```bash
adb shell run-as com.target cat shared_prefs/auth.xml   # cleartext token = finding
# or, if allowBackup=true (no root):
adb backup -f b.ab com.target && dd if=b.ab bs=24 skip=1 | zlib-flate -uncompress | tar xv
```

## Validation — MASVS Gate-0

before writing the report, answer all three:

1. **Reachability** — can an *external* actor trigger this (another app, a deep link, a network response, a shared file), or only the app itself? app-internal-only is usually not a finding.
2. **Impact** — what does the attacker gain (data read/write, code execution, auth bypass, privilege gain) and which CIA property does the victim lose? map to `MASVS-STORAGE-1`.
3. **Reproducible in 10 min** — exact entry point (component/URI/intent) + payload + observed result (leaked data / state change / execution), on a clean install, no pre-seeded state.

if any answer is weak, it's a static lead — keep hunting, don't file.

## Chains

cleartext session token -> direct account access; cross-ref `mhunt-insecure-file-permissions`.
