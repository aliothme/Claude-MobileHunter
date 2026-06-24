---
name: mhunt-fragment-injection
description: Mobile hunting skill for fragment injection on Android/iOS apps. Ported from droid-llm-hunter vuln_rule 'fragment_injection'. MASVS-PLATFORM-1 (Fragment Injection Prevention). Use when /hunt-mobile (via mhunt-dispatch) fires this rule's detection_pattern, or when hunting fragment injection in a decompiled app.
source: droid-llm-hunter (config/prompts/vuln_rules/fragment_injection.yaml)
masvs: MASVS-PLATFORM-1
---

# mhunt-fragment-injection

port of droid-llm-hunter's `fragment_injection` vuln_rule into the `/hunt-mobile` model. **Fragment Injection** — An exported Activity extending `PreferenceActivity` that doesn't override `isValidFragment` (or returns true) lets an attacker load *any* fragment via `:android:show_fragment` -> reach internal/privileged screens, sometimes RCE.

## MASVS

`MASVS-PLATFORM-1` — Fragment Injection Prevention. likely severity: **High** (confirm via the Gate-0 below; mobile severity depends on reachability + impact, not the pattern alone).

## Detection signal (the rule's `detection_pattern`)

android (smali/java/xml) — grep verbatim:

```
.super Landroid/preference/PreferenceActivity;
```

ios parallel: (n/a)

a regex hit is a **lead, not a finding** — droid-llm-hunter then deep-scans it with the LLM. that deep-scan is the methodology below.

## Static methodology (deep scan)

- Find classes extending `PreferenceActivity` (`.super Landroid/preference/PreferenceActivity;`).
- Check the activity is exported AND `isValidFragment(String)` is missing or `return true`.
- If so, `EXTRA_SHOW_FRAGMENT`/`:android:show_fragment` lets the attacker instantiate any Fragment class with attacker args.

## Dynamic confirmation

- Start the activity forcing a sensitive fragment: confirm it renders out of context (e.g. a credentials/admin fragment).

device prereqs: rooted Android emulator/device with `adb` + `frida-server` (and `drozer`/`objection` where noted), or a jailbroken iOS device with `frida`/`objection`. no device -> report as a static-only lead, don't claim confirmed.

## PoC

```bash
adb shell am start -n com.target/.SettingsActivity \
  --es ':android:show_fragment' 'com.target.internal.AdminPrefsFragment'
```

## Validation — MASVS Gate-0

before writing the report, answer all three:

1. **Reachability** — can an *external* actor trigger this (another app, a deep link, a network response, a shared file), or only the app itself? app-internal-only is usually not a finding.
2. **Impact** — what does the attacker gain (data read/write, code execution, auth bypass, privilege gain) and which CIA property does the victim lose? map to `MASVS-PLATFORM-1`.
3. **Reproducible in 10 min** — exact entry point (component/URI/intent) + payload + observed result (leaked data / state change / execution), on a clean install, no pre-seeded state.

if any answer is weak, it's a static lead — keep hunting, don't file.

## Chains

load a fragment that exposes WebView/auth state -> escalate; pre-KitKat targets can reach RCE.
