---
name: mhunt-deeplink-logic-bypass
description: Mobile hunting skill for deep link logic bypass on Android/iOS apps. Ported from droid-llm-hunter vuln_rule 'deeplink_logic_bypass'. MASVS-PLATFORM-1 (Deep Link Logic Bypass Prevention). Use when /hunt-mobile (via mhunt-dispatch) fires this rule's detection_pattern, or when hunting deep link logic bypass in a decompiled app.
source: droid-llm-hunter (config/prompts/vuln_rules/deeplink_logic_bypass.yaml)
masvs: MASVS-PLATFORM-1
---

# mhunt-deeplink-logic-bypass

port of droid-llm-hunter's `deeplink_logic_bypass` vuln_rule into the `/hunt-mobile` model. **Deep Link Logic Bypass** — Deep-link handler pulls sensitive params (`token`,`url`,`redirect`,`next`) from the URI with missing or weak validation (`startsWith('http')`, `contains`) -> IDOR, auth bypass, or open redirect into a WebView.

## MASVS

`MASVS-PLATFORM-1` — Deep Link Logic Bypass Prevention. likely severity: **High** (confirm via the Gate-0 below; mobile severity depends on reachability + impact, not the pattern alone).

## Detection signal (the rule's `detection_pattern`)

android (smali/java/xml) — grep verbatim:

```
(?i)(\.(getQueryParameter|getData)|Uri\.parse|scheme|host)
```

ios parallel: `application:openURL:` / `continueUserActivity:` reading `url`/`token`/`redirect` query items with weak `hasPrefix:` validation

a regex hit is a **lead, not a finding** — droid-llm-hunter then deep-scans it with the LLM. that deep-scan is the methodology below.

## Static methodology (deep scan)

- Find `getQueryParameter("token"|"url"|"redirect"|"next")` and check how each is validated before use.
- Weak checks to flag: `startsWith("http")` (bypass `http.evil.com`), `contains("target.com")` (bypass `target.com.evil`), no check at all.
- Sensitive params used directly (auth token, user id) without session verification = auth bypass / IDOR.
- `intent.setData(Uri.parse(param))` or `webview.loadUrl(param)` without host check = open redirect.

## Dynamic confirmation

- Supply a malicious value and confirm: `adb shell am start -a android.intent.action.VIEW -d 'myapp://reset?token=GUESSED&redirect=//attacker'`.

device prereqs: rooted Android emulator/device with `adb` + `frida-server` (and `drozer`/`objection` where noted), or a jailbroken iOS device with `frida`/`objection`. no device -> report as a static-only lead, don't claim confirmed.

## PoC

```bash
# weak startsWith('https://target') bypass:
adb shell am start -a android.intent.action.VIEW \
  -d 'myapp://go?redirect=https://target.com.attacker.example/'
```

## Validation — MASVS Gate-0

before writing the report, answer all three:

1. **Reachability** — can an *external* actor trigger this (another app, a deep link, a network response, a shared file), or only the app itself? app-internal-only is usually not a finding.
2. **Impact** — what does the attacker gain (data read/write, code execution, auth bypass, privilege gain) and which CIA property does the victim lose? map to `MASVS-PLATFORM-1`.
3. **Reproducible in 10 min** — exact entry point (component/URI/intent) + payload + observed result (leaked data / state change / execution), on a clean install, no pre-seeded state.

if any answer is weak, it's a static lead — keep hunting, don't file.

## Chains

open-redirect deep link + OAuth -> token theft; param-trusted user id -> IDOR (`mhunt-universal-logic-flaw`).
