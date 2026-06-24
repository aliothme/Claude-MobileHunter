---
name: mhunt-sql-injection
description: Mobile hunting skill for mobile sql injection on Android/iOS apps. Ported from droid-llm-hunter vuln_rule 'sql_injection'. MASVS-CODE-4 (SQL Injection Prevention). Use when /hunt-mobile (via mhunt-dispatch) fires this rule's detection_pattern, or when hunting mobile sql injection in a decompiled app.
source: droid-llm-hunter (config/prompts/vuln_rules/sql_injection.yaml)
masvs: MASVS-CODE-4
---

# mhunt-sql-injection

port of droid-llm-hunter's `sql_injection` vuln_rule into the `/hunt-mobile` model. **Mobile SQL Injection** — User input concatenated directly into SQL executed via `rawQuery` / `execSQL` (Android SQLite) or `sqlite3_exec` / FMDB (iOS).

## MASVS

`MASVS-CODE-4` — SQL Injection Prevention. likely severity: **High** (confirm via the Gate-0 below; mobile severity depends on reachability + impact, not the pattern alone).

## Detection signal (the rule's `detection_pattern`)

android (smali/java/xml) — grep verbatim:

```
(rawQuery|execSQL)\s*\(
```

ios parallel: `stringWithFormat:` building a query passed to `sqlite3_exec` / FMDB `executeQuery:` with `%@` interpolation of user input

a regex hit is a **lead, not a finding** — droid-llm-hunter then deep-scans it with the LLM. that deep-scan is the methodology below.

## Static methodology (deep scan)

- Find every `rawQuery(`/`execSQL(` call and trace each argument back to its source.
- Flag any query string built with `+` concatenation or `String.format`/`stringWithFormat:` where a token comes from an Intent extra, deep-link param, IPC, exported provider, or file/network input.
- Safe = bound params (`?` placeholders + selectionArgs). Concatenation of attacker-reachable input = vulnerable.

## Dynamic confirmation

- If the sink is reachable through an exported ContentProvider, query it with `drozer`: `run app.provider.query content://<authority>/<path> --selection "1=1) UNION SELECT ..."`.
- Hook the query method with Frida and inject `' OR '1'='1` to confirm the string reaches SQLite unsanitized.

device prereqs: rooted Android emulator/device with `adb` + `frida-server` (and `drozer`/`objection` where noted), or a jailbroken iOS device with `frida`/`objection`. no device -> report as a static-only lead, don't claim confirmed.

## PoC

```bash
# exported provider reachable from any app on device:
adb shell content query --uri content://com.target.provider/users \
  --where "name='x' UNION SELECT password,1 FROM secrets--"
```

## Validation — MASVS Gate-0

before writing the report, answer all three:

1. **Reachability** — can an *external* actor trigger this (another app, a deep link, a network response, a shared file), or only the app itself? app-internal-only is usually not a finding.
2. **Impact** — what does the attacker gain (data read/write, code execution, auth bypass, privilege gain) and which CIA property does the victim lose? map to `MASVS-CODE-4`.
3. **Reproducible in 10 min** — exact entry point (component/URI/intent) + payload + observed result (leaked data / state change / execution), on a clean install, no pre-seeded state.

if any answer is weak, it's a static lead — keep hunting, don't file.

## Chains

A provider SQLi that leaks a session token feeds `mhunt-universal-logic-flaw` (auth bypass) or an account-takeover chain.
