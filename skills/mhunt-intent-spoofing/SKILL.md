---
name: mhunt-intent-spoofing
description: Mobile hunting skill for intent spoofing on Android/iOS apps. Ported from droid-llm-hunter vuln_rule 'intent_spoofing'. MASVS-PLATFORM-1 (Intent Spoofing Vulnerability). Use when /hunt-mobile (via mhunt-dispatch) fires this rule's detection_pattern, or when hunting intent spoofing in a decompiled app.
source: droid-llm-hunter (config/prompts/vuln_rules/intent_spoofing.yaml)
masvs: MASVS-PLATFORM-1
---

# mhunt-intent-spoofing

port of droid-llm-hunter's `intent_spoofing` vuln_rule into the `/hunt-mobile` model. **Intent Spoofing** — Exported component with no (or weak) permission trusts the incoming Intent's action/extras, so a malicious app spoofs an Intent to drive privileged behavior.

## MASVS

`MASVS-PLATFORM-1` — Intent Spoofing Vulnerability. likely severity: **Medium** (confirm via the Gate-0 below; mobile severity depends on reachability + impact, not the pattern alone).

## Detection signal (the rule's `detection_pattern`)

android (smali/java/xml) — grep verbatim:

```
android:exported=[\"']true[\"']
```

ios parallel: forged inputs to `application:openURL:` / custom-scheme handlers or NSExtension request handling

a regex hit is a **lead, not a finding** — droid-llm-hunter then deep-scans it with the LLM. that deep-scan is the methodology below.

## Static methodology (deep scan)

- For each exported component lacking a strong permission, find where it reads `getAction()`/`getStringExtra()`/`getParcelableExtra()` and trusts them for a security decision.
- Classic: an exported BroadcastReceiver that performs a privileged action when it receives a specific action string an attacker can send.
- Also check `getCallingPackage()`/`getCallingActivity()` returning null (started via startActivity, not ForResult) and the code assuming a trusted caller.

## Dynamic confirmation

- Send a spoofed Intent with crafted extras via `am`/`drozer` and confirm the privileged action fires.

device prereqs: rooted Android emulator/device with `adb` + `frida-server` (and `drozer`/`objection` where noted), or a jailbroken iOS device with `frida`/`objection`. no device -> report as a static-only lead, don't claim confirmed.

## PoC

```bash
adb shell am broadcast -a com.target.ACTION_GRANT_PREMIUM \
  -n com.target/.PremiumReceiver --ez granted true
```

## Validation — MASVS Gate-0

before writing the report, answer all three:

1. **Reachability** — can an *external* actor trigger this (another app, a deep link, a network response, a shared file), or only the app itself? app-internal-only is usually not a finding.
2. **Impact** — what does the attacker gain (data read/write, code execution, auth bypass, privilege gain) and which CIA property does the victim lose? map to `MASVS-PLATFORM-1`.
3. **Reproducible in 10 min** — exact entry point (component/URI/intent) + payload + observed result (leaked data / state change / execution), on a clean install, no pre-seeded state.

if any answer is weak, it's a static lead — keep hunting, don't file.

## Chains

spoofed intent -> internal state change; combine with `mhunt-exported-components`, `mhunt-pending-intent-hijacking`.
