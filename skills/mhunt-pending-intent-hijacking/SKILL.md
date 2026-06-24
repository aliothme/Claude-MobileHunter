---
name: mhunt-pending-intent-hijacking
description: Mobile hunting skill for pendingintent hijacking on Android/iOS apps. Ported from droid-llm-hunter vuln_rule 'pending_intent_hijacking'. MASVS-PLATFORM-1 (PendingIntent Hijacking Prevention). Use when /hunt-mobile (via mhunt-dispatch) fires this rule's detection_pattern, or when hunting pendingintent hijacking in a decompiled app.
source: droid-llm-hunter (config/prompts/vuln_rules/pending_intent_hijacking.yaml)
masvs: MASVS-PLATFORM-1
---

# mhunt-pending-intent-hijacking

port of droid-llm-hunter's `pending_intent_hijacking` vuln_rule into the `/hunt-mobile` model. **PendingIntent Hijacking** — A mutable PendingIntent (FLAG_MUTABLE, or pre-S code omitting FLAG_IMMUTABLE) handed to another app/component lets the recipient fill in the blank base Intent and execute it with the *sender's* identity/permissions -> privilege escalation.

## MASVS

`MASVS-PLATFORM-1` — PendingIntent Hijacking Prevention. likely severity: **High** (confirm via the Gate-0 below; mobile severity depends on reachability + impact, not the pattern alone).

## Detection signal (the rule's `detection_pattern`)

android (smali/java/xml) — grep verbatim:

```
PendingIntent\.(getActivity|getService|getBroadcast).*FLAG_MUTABLE
```

ios parallel: (n/a direct; analogue is passing a mutable callback/handler across an XPC boundary)

a regex hit is a **lead, not a finding** — droid-llm-hunter then deep-scans it with the LLM. that deep-scan is the methodology below.

## Static methodology (deep scan)

- Find `PendingIntent.getActivity/getService/getBroadcast`; flag any with `FLAG_MUTABLE` or, on pre-Android-12 targets, missing `FLAG_IMMUTABLE`.
- Critical when the base Intent is empty/implicit AND the PendingIntent is passed to an external component (notification, bubble, third-party SDK, exported component).
- An empty mutable PendingIntent = attacker sets component+data and runs it as the victim app.

## Dynamic confirmation

- Receive the PendingIntent (e.g. via the exported surface that hands it out), `fillIn()` a malicious Intent targeting an internal protected component, and `send()`.

device prereqs: rooted Android emulator/device with `adb` + `frida-server` (and `drozer`/`objection` where noted), or a jailbroken iOS device with `frida`/`objection`. no device -> report as a static-only lead, don't claim confirmed.

## PoC

```java
// attacker holding the mutable PendingIntent:
Intent evil = new Intent();
evil.setClassName("com.target", "com.target.InternalAction");
evil.putExtra("amount", -1000);
pendingIntent.send(ctx, 0, evil);   // runs with com.target's identity
```

## Validation — MASVS Gate-0

before writing the report, answer all three:

1. **Reachability** — can an *external* actor trigger this (another app, a deep link, a network response, a shared file), or only the app itself? app-internal-only is usually not a finding.
2. **Impact** — what does the attacker gain (data read/write, code execution, auth bypass, privilege gain) and which CIA property does the victim lose? map to `MASVS-PLATFORM-1`.
3. **Reproducible in 10 min** — exact entry point (component/URI/intent) + payload + observed result (leaked data / state change / execution), on a clean install, no pre-seeded state.

if any answer is weak, it's a static lead — keep hunting, don't file.

## Chains

mutable PendingIntent -> invoke an internal protected component -> the bug that component holds (intent-spoofing / logic).
