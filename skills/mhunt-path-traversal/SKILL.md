---
name: mhunt-path-traversal
description: Mobile hunting skill for path traversal (contentprovider) on Android/iOS apps. Ported from droid-llm-hunter vuln_rule 'path_traversal'. MASVS-CODE-4 (Path Traversal Attack Prevention). Use when /hunt-mobile (via mhunt-dispatch) fires this rule's detection_pattern, or when hunting path traversal (contentprovider) in a decompiled app.
source: droid-llm-hunter (config/prompts/vuln_rules/path_traversal.yaml)
masvs: MASVS-CODE-4
---

# mhunt-path-traversal

port of droid-llm-hunter's `path_traversal` vuln_rule into the `/hunt-mobile` model. **Path Traversal (ContentProvider)** — A ContentProvider's `openFile()` builds the served file path from the request URI without canonicalizing/validating it, so `../` escapes the intended directory and reads arbitrary app-private files.

## MASVS

`MASVS-CODE-4` — Path Traversal Attack Prevention. likely severity: **High** (confirm via the Gate-0 below; mobile severity depends on reachability + impact, not the pattern alone).

## Detection signal (the rule's `detection_pattern`)

android (smali/java/xml) — grep verbatim:

```
openFile
```

ios parallel: `application:openURL:` or a file-serving handler building paths from input without canonicalization

a regex hit is a **lead, not a finding** — droid-llm-hunter then deep-scans it with the LLM. that deep-scan is the methodology below.

## Static methodology (deep scan)

- Find `openFile(Uri, String)` in ContentProviders; check whether the path segment is used to build a `File` without `getCanonicalPath()` + base-dir prefix check.
- Vulnerable: `new File(baseDir, uri.getLastPathSegment())` / decoding the path straight into a File.
- Reachable from any app if the provider is exported / grants URI permissions.

## Dynamic confirmation

- `adb shell content read --uri 'content://com.target.fileprovider/files/..%2F..%2Fdatabases%2Fauth.db'`.
- drozer: `run app.provider.read content://...../../../etc/hosts`.

device prereqs: rooted Android emulator/device with `adb` + `frida-server` (and `drozer`/`objection` where noted), or a jailbroken iOS device with `frida`/`objection`. no device -> report as a static-only lead, don't claim confirmed.

## PoC

```bash
adb shell content read \
  --uri 'content://com.target.provider/cache/..%2F..%2Fshared_prefs%2Fauth.xml'
```

## Validation — MASVS Gate-0

before writing the report, answer all three:

1. **Reachability** — can an *external* actor trigger this (another app, a deep link, a network response, a shared file), or only the app itself? app-internal-only is usually not a finding.
2. **Impact** — what does the attacker gain (data read/write, code execution, auth bypass, privilege gain) and which CIA property does the victim lose? map to `MASVS-CODE-4`.
3. **Reproducible in 10 min** — exact entry point (component/URI/intent) + payload + observed result (leaked data / state change / execution), on a clean install, no pre-seeded state.

if any answer is weak, it's a static lead — keep hunting, don't file.

## Chains

arbitrary file read -> harvest tokens/DB (`mhunt-insecure-storage`) -> account access.
