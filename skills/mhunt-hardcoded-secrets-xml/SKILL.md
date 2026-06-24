---
name: mhunt-hardcoded-secrets-xml
description: Mobile hunting skill for hardcoded secrets (strings.xml) on Android/iOS apps. Ported from droid-llm-hunter vuln_rule 'hardcoded_secrets_xml'. MASVS-STORAGE-2 (Hardcoded Secrets in Resources). Use when /hunt-mobile (via mhunt-dispatch) fires this rule's detection_pattern, or when hunting hardcoded secrets (strings.xml) in a decompiled app.
source: droid-llm-hunter (config/prompts/vuln_rules/hardcoded_secrets_xml.yaml)
masvs: MASVS-STORAGE-2
---

# mhunt-hardcoded-secrets-xml

port of droid-llm-hunter's `hardcoded_secrets_xml` vuln_rule into the `/hunt-mobile` model. **Hardcoded Secrets (strings.xml)** — Sensitive keys hidden in `res/values/strings.xml` (or other resource XML) — trivially extracted, often missed because they're not in code.

## MASVS

`MASVS-STORAGE-2` — Hardcoded Secrets in Resources. likely severity: **Medium** (confirm via the Gate-0 below; mobile severity depends on reachability + impact, not the pattern alone).

## Detection signal (the rule's `detection_pattern`)

android (smali/java/xml) — grep verbatim:

```
res/values/strings\.xml string name containing api_key|secret|aws_key|private_key|firebase_url
```

ios parallel: secrets in `Info.plist`, `*.plist` config bundles, or `Settings.bundle`

a regex hit is a **lead, not a finding** — droid-llm-hunter then deep-scans it with the LLM. that deep-scan is the methodology below.

## Static methodology (deep scan)

- Scan `res/values/strings.xml` for string names like `api_key`, `google_api_key`, `aws_key`, `secret`, `private_key`, `firebase_url`, `gcm_defaultSenderId`.
- Flag high-entropy values (`AIza...`, `sk-...`, `AKIA...`); ignore obvious UI copy and placeholders.
- `google_api_key`/`firebase_url` -> check Firebase rules for public read (often the real bug).

## Dynamic confirmation

- `grep -rEn 'AIza|AKIA|firebaseio|amazonaws' apktool/res/values*/strings.xml`.
- Test the Firebase DB open: `curl https://<project>.firebaseio.com/.json` -> data = misconfig.

device prereqs: rooted Android emulator/device with `adb` + `frida-server` (and `drozer`/`objection` where noted), or a jailbroken iOS device with `frida`/`objection`. no device -> report as a static-only lead, don't claim confirmed.

## PoC

```bash
curl -s "https://<project>.firebaseio.com/.json" | head      # 200+data = world-readable
```

## Validation — MASVS Gate-0

before writing the report, answer all three:

1. **Reachability** — can an *external* actor trigger this (another app, a deep link, a network response, a shared file), or only the app itself? app-internal-only is usually not a finding.
2. **Impact** — what does the attacker gain (data read/write, code execution, auth bypass, privilege gain) and which CIA property does the victim lose? map to `MASVS-STORAGE-2`.
3. **Reproducible in 10 min** — exact entry point (component/URI/intent) + payload + observed result (leaked data / state change / execution), on a clean install, no pre-seeded state.

if any answer is weak, it's a static lead — keep hunting, don't file.

## Chains

firebase_url + open rules -> full DB read/write; cross-ref `mhunt-hardcoded-secrets`.
