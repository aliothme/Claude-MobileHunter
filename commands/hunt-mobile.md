---
name: hunt-mobile
description: Active mobile-app vulnerability hunting. Port of droid-llm-hunter's vuln_rules to the /hunt model. Decompiles an APK/IPA, runs the LLM-SAST pipeline, maps detection signals to mhunt-* skills, hunts statically + dynamically. Usage: /hunt-mobile app.apk | /hunt-mobile app.ipa | /hunt-mobile <package> [--platform android|ios] [--mode static|dynamic|hybrid] [--vuln-class X]
---

# /hunt-mobile

slim mobile dispatcher. parse the target, settle platform + filter mode, hand off to the `mhunt-dispatch` skill. never asks about SOW — invoking `/hunt-mobile` implies SOW is signed and the build is authorized for testing.

mirrors `/hunt` exactly in shape; the difference is the target is a mobile binary (APK/IPA) or installed package, the analysis starts from decompiled code, and the loaded skills are the 26 `mhunt-*` ports of droid-llm-hunter's `vuln_rules`.

## step 0 — parse

```
app.apk | *.apk            android binary on disk
app.ipa | *.ipa            ios binary on disk
<package.name>             installed package — pull via adb / frida-ios-dump first
--platform android|ios     skip the platform question (auto-detected from extension when possible)
--mode static|dynamic|hybrid   filter_mode (droid-llm-hunter parlance); default hybrid
--vuln-class <X>           skip risk-identification, load only mhunt-<X>
--src <path>               already-decompiled source tree (skip the decompile stage)
```

extension → platform: `.apk`/`.aab`/`.dex` → android, `.ipa`/`.app` → ios. a bare package name with no extension → ask.

## step 1 — platform dispatcher

skipped if `--platform` is set or the extension is unambiguous.

```
question: "android or ios build?"
header:   "platform"
options:
  1. Android   — APK/AAB; apktool + jadx; Smali/Java; AndroidManifest.xml
  2. iOS       — IPA; unzip + class-dump / Hopper; Mach-O/Swift; Info.plist
```

## step 2 — filter mode (droid-llm-hunter's filter_mode)

```
question: "how deep — static, dynamic, or hybrid?"
header:   "mode"
options:
  1. Hybrid   (recommended)  — static decompile pass THEN runtime confirmation (drozer/objection/Frida)
  2. Static   — decompile + signal grep + LLM deep-scan only; no device needed
  3. Dynamic  — assume static already done; go straight to runtime exploitation on a rooted/jailbroken device or emulator
```

device note: dynamic/hybrid need a rooted Android emulator (or device) with `adb` + `frida-server`, or a jailbroken iOS device with `frida`/`objection`. if none is available, fall back to static and say so — do not silently skip the runtime confirmation step.

## step 3 — hand off

invoke the `mhunt-dispatch` skill:

```
mhunt-dispatch platform=android mode=hybrid target=<path>
mhunt-dispatch platform=ios     mode=static target=<path>
```

`mhunt-dispatch` runs the droid-llm-hunter pipeline: decompile → scope filter → risk identification (grep every rule's `detection_pattern`) → load the matched `mhunt-*` skills (cap 8) → print the taxonomy → return control here for deep-scan + exploitation.

if `--vuln-class <X>` is set, skip risk-identification and tell `mhunt-dispatch` to load only `mhunt-<X>`.

## step 4 — active testing

hand off to the loaded `mhunt-*` skills. each carries its own `detection_pattern`, methodology (static + dynamic), PoC, and MASVS validation gate. do not duplicate that logic here. on every confirmed primitive, check the chains section of the firing skill (and `mhunt-universal-logic-flaw`) for a composition into a higher-severity finding.

## step 5 — sibling delegation

```
before pulling a package off a device  →  confirm authorization + device ownership
5+ rules fire on one component          →  rank by MASVS severity, hunt highest-impact first
confirmed finding                       →  /chain (A→B composition, if the web /hunt suite is installed)
before any report                       →  /validate (or the per-skill Gate-0)
findings ready                          →  /report (suggest, never auto)
session end                             →  /remember (silent)
```

## modes recap

- `--mode static` → SAST only; no device. Good for triage / CI.
- `--mode dynamic` → runtime only; assumes you already know the candidate sinks.
- `--mode hybrid` → static finds the sink, dynamic proves it. Default. Highest signal.
- `--vuln-class <X>` → load only `mhunt-<X>` (e.g. `mhunt-webview-xss`), skip the grep triage.

## pacing & isolation

decompiled apps are large. cap the deep-scan at the 8 highest-MASVS-severity rules that fired (see `mhunt-dispatch` load budget). 20-min rotation: if a sink isn't confirming, note it as a static-only lead and move on. one session per build; findings scoped per-package in hunt memory.

## privacy

never echo or persist SOW / engagement-letter content. extracted APK/IPA contents, decompiled source, and any harvested secrets live only in a `.gitignore`d working dir — never commit them, never paste live secrets into a report (redact to first/last 4 chars).

at session end, invoke `/remember` silently (non-fatal).
