---
name: mhunt-unsafe-reflection
description: Mobile hunting skill for unsafe reflection on Android/iOS apps. Ported from droid-llm-hunter vuln_rule 'unsafe_reflection'. MASVS-CODE-4 (Unsafe Reflection Usage). Use when /hunt-mobile (via mhunt-dispatch) fires this rule's detection_pattern, or when hunting unsafe reflection in a decompiled app.
source: droid-llm-hunter (config/prompts/vuln_rules/unsafe_reflection.yaml)
masvs: MASVS-CODE-4
---

# mhunt-unsafe-reflection

port of droid-llm-hunter's `unsafe_reflection` vuln_rule into the `/hunt-mobile` model. **Unsafe Reflection** — `Class.forName`/`Method.invoke`/`ClassLoader.loadClass` driven by an attacker-controlled string (Intent extra, deep-link param) instantiates arbitrary classes / invokes arbitrary methods -> code execution.

## MASVS

`MASVS-CODE-4` — Unsafe Reflection Usage. likely severity: **High** (confirm via the Gate-0 below; mobile severity depends on reachability + impact, not the pattern alone).

## Detection signal (the rule's `detection_pattern`)

android (smali/java/xml) — grep verbatim:

```
(?i)(Class\.forName|Method\.invoke|ClassLoader\.loadClass)
```

ios parallel: `NSClassFromString`/`NSSelectorFromString` + `performSelector:` with externally-derived names

a regex hit is a **lead, not a finding** — droid-llm-hunter then deep-scans it with the LLM. that deep-scan is the methodology below.

## Static methodology (deep scan)

- Find reflection sinks and trace the class/method-name argument to its source.
- Pattern: `String cls = intent.getStringExtra("class"); Class.forName(cls)...` reachable via an exported component = RCE-grade.
- Combined with `DexClassLoader` loading an attacker-supplied dex = full code execution.

## Dynamic confirmation

- Send the class/method name through the reachable entry point and confirm instantiation/invocation of a chosen class.

device prereqs: rooted Android emulator/device with `adb` + `frida-server` (and `drozer`/`objection` where noted), or a jailbroken iOS device with `frida`/`objection`. no device -> report as a static-only lead, don't claim confirmed.

## PoC

```bash
adb shell am start -n com.target/.RouterActivity \
  --es targetClass 'com.target.internal.DebugRce' --es method 'run'
```

## Validation — MASVS Gate-0

before writing the report, answer all three:

1. **Reachability** — can an *external* actor trigger this (another app, a deep link, a network response, a shared file), or only the app itself? app-internal-only is usually not a finding.
2. **Impact** — what does the attacker gain (data read/write, code execution, auth bypass, privilege gain) and which CIA property does the victim lose? map to `MASVS-CODE-4`.
3. **Reproducible in 10 min** — exact entry point (component/URI/intent) + payload + observed result (leaked data / state change / execution), on a clean install, no pre-seeded state.

if any answer is weak, it's a static lead — keep hunting, don't file.

## Chains

reflection + DexClassLoader (`mhunt-library-supply-chain`) -> load+run attacker dex = RCE.
