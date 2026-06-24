---
name: mhunt-insecure-file-permissions
description: Mobile hunting skill for insecure file permissions on Android/iOS apps. Ported from droid-llm-hunter vuln_rule 'insecure_file_permissions'. MASVS-STORAGE-1 (Insecure File Permissions). Use when /hunt-mobile (via mhunt-dispatch) fires this rule's detection_pattern, or when hunting insecure file permissions in a decompiled app.
source: droid-llm-hunter (config/prompts/vuln_rules/insecure_file_permissions.yaml)
masvs: MASVS-STORAGE-1
---

# mhunt-insecure-file-permissions

port of droid-llm-hunter's `insecure_file_permissions` vuln_rule into the `/hunt-mobile` model. **Insecure File Permissions** — `openFileOutput`/file creation with `MODE_WORLD_READABLE`/`MODE_WORLD_WRITABLE` (deprecated since API 17, throws on 24+) exposes app files to every other app on the device.

## MASVS

`MASVS-STORAGE-1` — Insecure File Permissions. likely severity: **Medium** (confirm via the Gate-0 below; mobile severity depends on reachability + impact, not the pattern alone).

## Detection signal (the rule's `detection_pattern`)

android (smali/java/xml) — grep verbatim:

```
MODE_WORLD_READABLE|MODE_WORLD_WRITABLE
```

ios parallel: files written to a Shared App Group container or `Documents` with no protection class (`NSFileProtectionNone`)

a regex hit is a **lead, not a finding** — droid-llm-hunter then deep-scans it with the LLM. that deep-scan is the methodology below.

## Static methodology (deep scan)

- Find every `openFileOutput(name, MODE_WORLD_*)` and `File`/`chmod` granting world perms.
- World-writable is worse than world-readable — another app overwrites the file (config/poisoning).

## Dynamic confirmation

- `adb shell ls -l /data/data/com.target/files/` -> any `-rw-rw-rw-`/`o+r` is the bug.
- From a second unprivileged app, read/write the file to prove cross-app reach.

device prereqs: rooted Android emulator/device with `adb` + `frida-server` (and `drozer`/`objection` where noted), or a jailbroken iOS device with `frida`/`objection`. no device -> report as a static-only lead, don't claim confirmed.

## PoC

```bash
adb shell ls -l /data/data/com.target/files/   # look for world bits (last triad r/w)
```

## Validation — MASVS Gate-0

before writing the report, answer all three:

1. **Reachability** — can an *external* actor trigger this (another app, a deep link, a network response, a shared file), or only the app itself? app-internal-only is usually not a finding.
2. **Impact** — what does the attacker gain (data read/write, code execution, auth bypass, privilege gain) and which CIA property does the victim lose? map to `MASVS-STORAGE-1`.
3. **Reproducible in 10 min** — exact entry point (component/URI/intent) + payload + observed result (leaked data / state change / execution), on a clean install, no pre-seeded state.

if any answer is weak, it's a static lead — keep hunting, don't file.

## Chains

world-writable config -> overwrite -> logic/redirect manipulation; world-readable -> token theft (`mhunt-insecure-storage`).
