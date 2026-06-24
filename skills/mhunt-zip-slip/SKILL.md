---
name: mhunt-zip-slip
description: Mobile hunting skill for zip slip path traversal on Android/iOS apps. Ported from droid-llm-hunter vuln_rule 'zip_slip'. MASVS-CODE-4 (Zip Slip Vulnerability Prevention). Use when /hunt-mobile (via mhunt-dispatch) fires this rule's detection_pattern, or when hunting zip slip path traversal in a decompiled app.
source: droid-llm-hunter (config/prompts/vuln_rules/zip_slip.yaml)
masvs: MASVS-CODE-4
---

# mhunt-zip-slip

port of droid-llm-hunter's `zip_slip` vuln_rule into the `/hunt-mobile` model. **Zip Slip Path Traversal** — Archive extraction builds the output path from `ZipEntry.getName()` without checking the resolved path stays inside the target dir, so a crafted entry name (`../../`) overwrites arbitrary files -> code/config overwrite, sometimes RCE.

## MASVS

`MASVS-CODE-4` — Zip Slip Vulnerability Prevention. likely severity: **High** (confirm via the Gate-0 below; mobile severity depends on reachability + impact, not the pattern alone).

## Detection signal (the rule's `detection_pattern`)

android (smali/java/xml) — grep verbatim:

```
ZipEntry.*\.getName
```

ios parallel: `unzip`/`SSZipArchive`/`NSFileManager` extraction using `entry.name` without canonical-path validation

a regex hit is a **lead, not a finding** — droid-llm-hunter then deep-scans it with the LLM. that deep-scan is the methodology below.

## Static methodology (deep scan)

- Find loops over `ZipInputStream`/`ZipFile.entries()` that do `new File(destDir, entry.getName())`.
- Confirm the MISSING check: `target.getCanonicalPath().startsWith(destDir.getCanonicalPath())`. Absent = vulnerable.
- Reachable if the archive comes from network, a deep link, an exported component, or an attacker-shared file.

## Dynamic confirmation

- Craft a zip with an entry named `../../<target>/file` and feed it through the import/update flow; confirm overwrite.

device prereqs: rooted Android emulator/device with `adb` + `frida-server` (and `drozer`/`objection` where noted), or a jailbroken iOS device with `frida`/`objection`. no device -> report as a static-only lead, don't claim confirmed.

## PoC

```python
import zipfile
z = zipfile.ZipFile('evil.zip','w')
z.writestr('../../../../data/data/com.target/files/config.json', '{"isAdmin":true}')
z.close()   # extraction without canonical check overwrites the real config
```

## Validation — MASVS Gate-0

before writing the report, answer all three:

1. **Reachability** — can an *external* actor trigger this (another app, a deep link, a network response, a shared file), or only the app itself? app-internal-only is usually not a finding.
2. **Impact** — what does the attacker gain (data read/write, code execution, auth bypass, privilege gain) and which CIA property does the victim lose? map to `MASVS-CODE-4`.
3. **Reproducible in 10 min** — exact entry point (component/URI/intent) + payload + observed result (leaked data / state change / execution), on a clean install, no pre-seeded state.

if any answer is weak, it's a static lead — keep hunting, don't file.

## Chains

overwrite a dex/so/config consumed at runtime -> code execution or privilege flip.
