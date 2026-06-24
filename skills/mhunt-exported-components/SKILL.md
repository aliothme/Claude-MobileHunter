---
name: mhunt-exported-components
description: Mobile hunting skill for exported components on Android/iOS apps. Ported from droid-llm-hunter vuln_rule 'exported_components'. MASVS-PLATFORM-1 (Exported Components Security). Use when /hunt-mobile (via mhunt-dispatch) fires this rule's detection_pattern, or when hunting exported components in a decompiled app.
source: droid-llm-hunter (config/prompts/vuln_rules/exported_components.yaml)
masvs: MASVS-PLATFORM-1
---

# mhunt-exported-components

port of droid-llm-hunter's `exported_components` vuln_rule into the `/hunt-mobile` model. **Exported Components** — Activities/Services/Receivers/Providers exported without a protecting permission are callable by any app on the device -> unauthorized actions, data access, or DoS.

## MASVS

`MASVS-PLATFORM-1` — Exported Components Security. likely severity: **Medium** (confirm via the Gate-0 below; mobile severity depends on reachability + impact, not the pattern alone).

## Detection signal (the rule's `detection_pattern`)

android (smali/java/xml) — grep verbatim:

```
android:exported=[\"']true[\"']
```

ios parallel: (n/a — iOS has no exported components; analogue is over-broad URL scheme / App Extension handling)

a regex hit is a **lead, not a finding** — droid-llm-hunter then deep-scans it with the LLM. that deep-scan is the methodology below.

## Static methodology (deep scan)

- List every component with `exported="true"` (or an intent-filter, which implies exported on older targets) AND no `android:permission`.
- For each, read the component code: what does an attacker-supplied Intent let them do? (start an internal screen, write a provider, trigger a privileged action).
- ContentProviders are highest-value — exported provider = direct data read/write (see `mhunt-path-traversal`, `mhunt-sql-injection`).

## Dynamic confirmation

- `drozer`: `run app.package.attacksurface com.target`, then `run app.activity.start`/`app.provider.query`/`app.service.start` against the exported ones.

device prereqs: rooted Android emulator/device with `adb` + `frida-server` (and `drozer`/`objection` where noted), or a jailbroken iOS device with `frida`/`objection`. no device -> report as a static-only lead, don't claim confirmed.

## PoC

```bash
# invoke an exported, unprotected activity directly:
adb shell am start -n com.target/.internal.AdminActivity --ez is_admin true
# query an exported provider:
adb shell content query --uri content://com.target.provider/data
```

## Validation — MASVS Gate-0

before writing the report, answer all three:

1. **Reachability** — can an *external* actor trigger this (another app, a deep link, a network response, a shared file), or only the app itself? app-internal-only is usually not a finding.
2. **Impact** — what does the attacker gain (data read/write, code execution, auth bypass, privilege gain) and which CIA property does the victim lose? map to `MASVS-PLATFORM-1`.
3. **Reproducible in 10 min** — exact entry point (component/URI/intent) + payload + observed result (leaked data / state change / execution), on a clean install, no pre-seeded state.

if any answer is weak, it's a static lead — keep hunting, don't file.

## Chains

exported component is the *entry point* for most other mobile bugs (intent-spoofing, fragment-injection, deserialization). cross-ref `mhunt-intent-spoofing`.
