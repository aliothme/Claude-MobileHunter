---
name: mhunt-insecure-random
description: Mobile hunting skill for weak random number generation on Android/iOS apps. Ported from droid-llm-hunter vuln_rule 'insecure_random_number_generation'. MASVS-CRYPTO-1 (Weak Random Number Generation). Use when /hunt-mobile (via mhunt-dispatch) fires this rule's detection_pattern, or when hunting weak random number generation in a decompiled app.
source: droid-llm-hunter (config/prompts/vuln_rules/insecure_random_number_generation.yaml)
masvs: MASVS-CRYPTO-1
---

# mhunt-insecure-random

port of droid-llm-hunter's `insecure_random_number_generation` vuln_rule into the `/hunt-mobile` model. **Weak Random Number Generation** — `java.util.Random` (a non-cryptographic LCG) used to generate security-sensitive values — tokens, OTPs, session IDs, IVs, password-reset codes — making them predictable.

## MASVS

`MASVS-CRYPTO-1` — Weak Random Number Generation. likely severity: **Medium** (confirm via the Gate-0 below; mobile severity depends on reachability + impact, not the pattern alone).

## Detection signal (the rule's `detection_pattern`)

android (smali/java/xml) — grep verbatim:

```
(Ljava/util/Random;|java\.util\.Random|new Random\()
```

ios parallel: `rand()`/`arc4random()` used for security tokens instead of `SecRandomCopyBytes`

a regex hit is a **lead, not a finding** — droid-llm-hunter then deep-scans it with the LLM. that deep-scan is the methodology below.

## Static methodology (deep scan)

- Find `new Random()`/`Ljava/util/Random;` and check what the output is used for. UI/animation = fine; tokens/OTP/keys/IV/nonces = vulnerable.
- Especially: password-reset codes, OTPs, CSRF/state values, file names for secrets. Must be `SecureRandom`/`SecRandomCopyBytes`.
- A `Random` seeded with `System.currentTimeMillis()` is fully predictable.

## Dynamic confirmation

- If it generates an OTP/reset code: collect several outputs, recover the LCG state, predict the next — confirms exploitability.

device prereqs: rooted Android emulator/device with `adb` + `frida-server` (and `drozer`/`objection` where noted), or a jailbroken iOS device with `frida`/`objection`. no device -> report as a static-only lead, don't claim confirmed.

## PoC

```text
java.util.Random is an LCG: given 2 consecutive outputs you can recover the 48-bit
seed and predict all future values. If the reset-code/OTP uses it, the code is guessable.
```

## Validation — MASVS Gate-0

before writing the report, answer all three:

1. **Reachability** — can an *external* actor trigger this (another app, a deep link, a network response, a shared file), or only the app itself? app-internal-only is usually not a finding.
2. **Impact** — what does the attacker gain (data read/write, code execution, auth bypass, privilege gain) and which CIA property does the victim lose? map to `MASVS-CRYPTO-1`.
3. **Reproducible in 10 min** — exact entry point (component/URI/intent) + payload + observed result (leaked data / state change / execution), on a clean install, no pre-seeded state.

if any answer is weak, it's a static lead — keep hunting, don't file.

## Chains

predictable reset token -> account takeover (the highest-impact form of this bug).
