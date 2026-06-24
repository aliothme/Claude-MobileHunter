---
name: mhunt-jetpack-compose
description: Mobile hunting skill for jetpack compose security on Android/iOS apps. Ported from droid-llm-hunter vuln_rule 'jetpack_compose_security'. MASVS-PLATFORM-3 (Jetpack Compose Security). Use when /hunt-mobile (via mhunt-dispatch) fires this rule's detection_pattern, or when hunting jetpack compose security in a decompiled app.
source: droid-llm-hunter (config/prompts/vuln_rules/jetpack_compose_security.yaml)
masvs: MASVS-PLATFORM-3
---

# mhunt-jetpack-compose

port of droid-llm-hunter's `jetpack_compose_security` vuln_rule into the `/hunt-mobile` model. **Jetpack Compose Security** — Composable screens showing sensitive data (credentials, OTP, payment, tokens) without `FLAG_SECURE` allow screen capture, screenshots, and recents-thumbnail leakage.

## MASVS

`MASVS-PLATFORM-3` — Jetpack Compose Security. likely severity: **Low** (confirm via the Gate-0 below; mobile severity depends on reachability + impact, not the pattern alone).

## Detection signal (the rule's `detection_pattern`)

android (smali/java/xml) — grep verbatim:

```
@Composable
```

ios parallel: SwiftUI screens with sensitive content not excluded from screenshots / `isSecureTextEntry` missing

a regex hit is a **lead, not a finding** — droid-llm-hunter then deep-scans it with the LLM. that deep-scan is the methodology below.

## Static methodology (deep scan)

- Find @Composable screens rendering sensitive fields; check the hosting Activity/Window sets `WindowManager.LayoutParams.FLAG_SECURE`.
- No FLAG_SECURE on a sensitive screen = it appears in screenshots, the recents thumbnail, and screen recordings/accessibility capture.
- Also check sensitive text fields lack secure input handling.

## Dynamic confirmation

- Open the sensitive screen, take a screenshot / view recents — content visible = confirmed. With FLAG_SECURE, capture is blocked.

device prereqs: rooted Android emulator/device with `adb` + `frida-server` (and `drozer`/`objection` where noted), or a jailbroken iOS device with `frida`/`objection`. no device -> report as a static-only lead, don't claim confirmed.

## PoC

```bash
adb shell screencap -p /sdcard/s.png && adb pull /sdcard/s.png
# sensitive screen content present in the image = missing FLAG_SECURE
```

## Validation — MASVS Gate-0

before writing the report, answer all three:

1. **Reachability** — can an *external* actor trigger this (another app, a deep link, a network response, a shared file), or only the app itself? app-internal-only is usually not a finding.
2. **Impact** — what does the attacker gain (data read/write, code execution, auth bypass, privilege gain) and which CIA property does the victim lose? map to `MASVS-PLATFORM-3`.
3. **Reproducible in 10 min** — exact entry point (component/URI/intent) + payload + observed result (leaked data / state change / execution), on a clean install, no pre-seeded state.

if any answer is weak, it's a static lead — keep hunting, don't file.

## Chains

low-severity alone; couples with malware/overlay scenarios or `mhunt-strandhogg` for credential capture.
