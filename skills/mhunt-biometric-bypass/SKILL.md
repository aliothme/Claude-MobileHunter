---
name: mhunt-biometric-bypass
description: Mobile hunting skill for biometric authentication bypass on Android/iOS apps. Ported from droid-llm-hunter vuln_rule 'biometric_bypass'. MASVS-AUTH-2 (Biometric Authentication Bypass). Use when /hunt-mobile (via mhunt-dispatch) fires this rule's detection_pattern, or when hunting biometric authentication bypass in a decompiled app.
source: droid-llm-hunter (config/prompts/vuln_rules/biometric_bypass.yaml)
masvs: MASVS-AUTH-2
---

# mhunt-biometric-bypass

port of droid-llm-hunter's `biometric_bypass` vuln_rule into the `/hunt-mobile` model. **Biometric Authentication Bypass** — `BiometricPrompt.onAuthenticationSucceeded` flips an app-controlled boolean rather than unlocking a Keystore-bound CryptoObject, so the success path can be forced (Frida) or reached via control-flow manipulation.

## MASVS

`MASVS-AUTH-2` — Biometric Authentication Bypass. likely severity: **High** (confirm via the Gate-0 below; mobile severity depends on reachability + impact, not the pattern alone).

## Detection signal (the rule's `detection_pattern`)

android (smali/java/xml) — grep verbatim:

```
BiometricPrompt
```

ios parallel: `LAContext evaluatePolicy:` whose boolean success gates logic but is not bound to a Keychain/Secure-Enclave key (`kSecAccessControlBiometryCurrentSet`)

a regex hit is a **lead, not a finding** — droid-llm-hunter then deep-scans it with the LLM. that deep-scan is the methodology below.

## Static methodology (deep scan)

- Check whether `authenticate()` passes a `CryptoObject` (key unlocked by the auth) or just a callback. Callback-only = the gate is a boolean in app memory.
- If `onAuthenticationSucceeded` merely sets `isAuthenticated=true` / navigates, the check is bypassable — no cryptographic binding.
- Secure pattern: biometric unlocks a Keystore key (setUserAuthenticationRequired) that decrypts the secret; you can't fake the key.

## Dynamic confirmation

- Frida: hook `onAuthenticationSucceeded` and call it directly, or force the success branch / overwrite the boolean.
- `objection`: `android hooking watch class androidx.biometric.BiometricPrompt`, then invoke the success callback.

device prereqs: rooted Android emulator/device with `adb` + `frida-server` (and `drozer`/`objection` where noted), or a jailbroken iOS device with `frida`/`objection`. no device -> report as a static-only lead, don't claim confirmed.

## PoC

```javascript
// Frida: directly invoke the success callback -> app unlocks without a fingerprint
Java.perform(function(){
  var cb = Java.use('com.target.LoginActivity$1'); // the callback impl
  cb.onAuthenticationSucceeded.implementation = function(r){ return this.onAuthenticationSucceeded(r); };
  // or call the post-auth navigate() method directly
});
```

## Validation — MASVS Gate-0

before writing the report, answer all three:

1. **Reachability** — can an *external* actor trigger this (another app, a deep link, a network response, a shared file), or only the app itself? app-internal-only is usually not a finding.
2. **Impact** — what does the attacker gain (data read/write, code execution, auth bypass, privilege gain) and which CIA property does the victim lose? map to `MASVS-AUTH-2`.
3. **Reproducible in 10 min** — exact entry point (component/URI/intent) + payload + observed result (leaked data / state change / execution), on a clean install, no pre-seeded state.

if any answer is weak, it's a static lead — keep hunting, don't file.

## Chains

local auth bypass -> access the locked feature; impactful when it guards payments / stored credentials.
