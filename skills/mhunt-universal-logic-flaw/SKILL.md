---
name: mhunt-universal-logic-flaw
description: Mobile hunting skill for universal logic flaw (ipc / reflection / business logic) on Android/iOS apps. Ported from droid-llm-hunter vuln_rule 'universal_logic_flaw'. MASVS (cross-cutting) (Conceptual Logic Flaw Detection). Use when /hunt-mobile (via mhunt-dispatch) fires this rule's detection_pattern, or when hunting universal logic flaw (ipc / reflection / business logic) in a decompiled app.
source: droid-llm-hunter (config/prompts/vuln_rules/universal_logic_flaw.yaml)
masvs: MASVS (cross-cutting)
---

# mhunt-universal-logic-flaw

port of droid-llm-hunter's `universal_logic_flaw` vuln_rule into the `/hunt-mobile` model. **Universal Logic Flaw (IPC / Reflection / Business Logic)** — The conceptual backstop rule (always loaded): subtle logic flaws the pattern rules miss — IPC/serialization object injection, reflection-driven execution, deep-link auth bypass, and business-logic abuse (negative-amount payments, client-trusted admin flags, transaction tampering).

## MASVS

`MASVS (cross-cutting)` — Conceptual Logic Flaw Detection. likely severity: **High** (confirm via the Gate-0 below; mobile severity depends on reachability + impact, not the pattern alone).

## Detection signal (the rule's `detection_pattern`)

android (smali/java/xml) — grep verbatim:

```
(Parcel|Serializable|Method\.invoke|Class\.forName|payment|admin|transfer|balance|shouldOverrideUrlLoading)
```

ios parallel: payment/auth/admin logic, `application:openURL:` routing, `NSCoding`, `performSelector:` — same devil's-advocate lens

a regex hit is a **lead, not a finding** — droid-llm-hunter then deep-scans it with the LLM. that deep-scan is the methodology below.

## Static methodology (deep scan)

- Adopt a devil's-advocate stance over the fired components and any payment/auth/admin code:
- Logic bypass: can input manipulation skip a critical `if (securityCheck)` block? race conditions on the check?
- Deserialization: does it accept `Serializable`/`Parcelable` from an external Intent? (object injection — see `mhunt-insecure-deserialization`)
- Reflection: is `Method.invoke`/`Class.forName` driven by user-controlled strings? (RCE — see `mhunt-unsafe-reflection`)
- Financial logic: can a negative/oversized amount be sent? is the `amount`/`isAdmin`/`role` trusted from client input?
- Deep-link auth: does `shouldOverrideUrlLoading` / a deep link reach an authenticated action without a session check?

## Dynamic confirmation

- For each candidate, articulate the kill chain and trigger it end-to-end (spoofed intent / crafted deep link / tampered request). If the code is robust, mark it Safe and move on.

device prereqs: rooted Android emulator/device with `adb` + `frida-server` (and `drozer`/`objection` where noted), or a jailbroken iOS device with `frida`/`objection`. no device -> report as a static-only lead, don't claim confirmed.

## PoC

```bash
# example: client-trusted admin flag via exported component
adb shell am start -n com.target/.Router --ez isAdmin true --es action upgrade
# example: negative-amount business-logic abuse on a client-built request (replay via proxy)
```

## Validation — MASVS Gate-0

before writing the report, answer all three:

1. **Reachability** — can an *external* actor trigger this (another app, a deep link, a network response, a shared file), or only the app itself? app-internal-only is usually not a finding.
2. **Impact** — what does the attacker gain (data read/write, code execution, auth bypass, privilege gain) and which CIA property does the victim lose? map to `MASVS (cross-cutting)`.
3. **Reproducible in 10 min** — exact entry point (component/URI/intent) + payload + observed result (leaked data / state change / execution), on a clean install, no pre-seeded state.

if any answer is weak, it's a static lead — keep hunting, don't file.

## Chains

this skill is where two confirmed primitives (e.g. exported write + insecure read) get composed into a single high-severity finding. It is the mobile analogue of `/chain`.
