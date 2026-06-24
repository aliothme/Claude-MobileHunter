---
name: mhunt-strandhogg
description: Mobile hunting skill for strandhogg task hijacking on Android/iOS apps. Ported from droid-llm-hunter vuln_rule 'strandhogg'. MASVS-PLATFORM-3 (StrandHogg Task Hijacking Prevention). Use when /hunt-mobile (via mhunt-dispatch) fires this rule's detection_pattern, or when hunting strandhogg task hijacking in a decompiled app.
source: droid-llm-hunter (config/prompts/vuln_rules/strandhogg.yaml)
masvs: MASVS-PLATFORM-3
---

# mhunt-strandhogg

port of droid-llm-hunter's `strandhogg` vuln_rule into the `/hunt-mobile` model. **StrandHogg Task Hijacking** — An exported Activity with `launchMode="singleTask"` (or a custom/empty `taskAffinity`) lets a malicious app insert its activity into the victim's task stack, overlaying a phishing/UI on top of the legitimate app (StrandHogg).

## MASVS

`MASVS-PLATFORM-3` — StrandHogg Task Hijacking Prevention. likely severity: **High** (confirm via the Gate-0 below; mobile severity depends on reachability + impact, not the pattern alone).

## Detection signal (the rule's `detection_pattern`)

android (smali/java/xml) — grep verbatim:

```
Activity: singleTask launch mode + exported=true + missing/uncontrolled taskAffinity
```

ios parallel: (n/a)

a regex hit is a **lead, not a finding** — droid-llm-hunter then deep-scans it with the LLM. that deep-scan is the methodology below.

## Static methodology (deep scan)

- In the manifest, flag activities combining `android:launchMode="singleTask"` (or `singleInstance`) + `exported="true"` + a `taskAffinity` that defaults to the package or is attacker-guessable.
- Also check `taskAffinity=""` and missing `FLAG_ACTIVITY_NEW_TASK` hygiene.
- Root cause: task reparenting/affinity lets another app's activity live in the victim's task.

## Dynamic confirmation

- Build a malicious app with a matching taskAffinity + allowTaskReparenting and confirm your activity surfaces over the target's task.

device prereqs: rooted Android emulator/device with `adb` + `frida-server` (and `drozer`/`objection` where noted), or a jailbroken iOS device with `frida`/`objection`. no device -> report as a static-only lead, don't claim confirmed.

## PoC

```xml
<!-- malicious app activity hijacks the victim's task via affinity match -->
<activity android:taskAffinity="com.target"
          android:allowTaskReparenting="true" android:exported="true"/>
```

## Validation — MASVS Gate-0

before writing the report, answer all three:

1. **Reachability** — can an *external* actor trigger this (another app, a deep link, a network response, a shared file), or only the app itself? app-internal-only is usually not a finding.
2. **Impact** — what does the attacker gain (data read/write, code execution, auth bypass, privilege gain) and which CIA property does the victim lose? map to `MASVS-PLATFORM-3`.
3. **Reproducible in 10 min** — exact entry point (component/URI/intent) + payload + observed result (leaked data / state change / execution), on a clean install, no pre-seeded state.

if any answer is weak, it's a static lead — keep hunting, don't file.

## Chains

task overlay -> credential phishing UI on top of the real app -> ATO. couples with `mhunt-jetpack-compose` (capture).
