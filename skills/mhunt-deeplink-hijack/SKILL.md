---
name: mhunt-deeplink-hijack
description: Mobile hunting skill for deep link hijacking & open redirect on Android/iOS apps. Ported from droid-llm-hunter vuln_rule 'deeplink_hijack'. MASVS-PLATFORM-1 (Deep Link Hijacking Prevention). Use when /hunt-mobile (via mhunt-dispatch) fires this rule's detection_pattern, or when hunting deep link hijacking & open redirect in a decompiled app.
source: droid-llm-hunter (config/prompts/vuln_rules/deeplink_hijack.yaml)
masvs: MASVS-PLATFORM-1
---

# mhunt-deeplink-hijack

port of droid-llm-hunter's `deeplink_hijack` vuln_rule into the `/hunt-mobile` model. **Deep Link Hijacking & Open Redirect** — A custom-scheme deep link with no host (or a wildcard) and no `autoVerify` can be claimed by a malicious app, hijacking the link and any data/tokens it carries.

## MASVS

`MASVS-PLATFORM-1` — Deep Link Hijacking Prevention. likely severity: **Medium** (confirm via the Gate-0 below; mobile severity depends on reachability + impact, not the pattern alone).

## Detection signal (the rule's `detection_pattern`)

android (smali/java/xml) — grep verbatim:

```
android:autoVerify|android:scheme
```

ios parallel: custom `CFBundleURLSchemes` (non-Universal-Link) that any app can also register; missing `apple-app-site-association` verification

a regex hit is a **lead, not a finding** — droid-llm-hunter then deep-scans it with the LLM. that deep-scan is the methodology below.

## Static methodology (deep scan)

- For each `<data android:scheme=...>` check whether a host is pinned and whether `android:autoVerify="true"` (App Links) is set.
- Custom scheme (`myapp://`) with no verification = hijackable by any app that registers the same scheme.
- Trace what sensitive data (tokens, codes) the link delivers to the activity.

## Dynamic confirmation

- Install a second app declaring the same scheme; trigger the link and confirm the disambiguation dialog / silent capture.

device prereqs: rooted Android emulator/device with `adb` + `frida-server` (and `drozer`/`objection` where noted), or a jailbroken iOS device with `frida`/`objection`. no device -> report as a static-only lead, don't claim confirmed.

## PoC

```xml
<!-- attacker app manifest claims the same scheme -> receives the OAuth code -->
<intent-filter><action android:name="android.intent.action.VIEW"/>
  <data android:scheme="myapp"/></intent-filter>
```

## Validation — MASVS Gate-0

before writing the report, answer all three:

1. **Reachability** — can an *external* actor trigger this (another app, a deep link, a network response, a shared file), or only the app itself? app-internal-only is usually not a finding.
2. **Impact** — what does the attacker gain (data read/write, code execution, auth bypass, privilege gain) and which CIA property does the victim lose? map to `MASVS-PLATFORM-1`.
3. **Reproducible in 10 min** — exact entry point (component/URI/intent) + payload + observed result (leaked data / state change / execution), on a clean install, no pre-seeded state.

if any answer is weak, it's a static lead — keep hunting, don't file.

## Chains

hijack the OAuth/magic-link redirect deep link -> account takeover. cross-ref `mhunt-deeplink-logic-bypass`.
