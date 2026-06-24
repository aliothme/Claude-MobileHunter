---
name: mhunt-graphql-injection
description: Mobile hunting skill for graphql injection on Android/iOS apps. Ported from droid-llm-hunter vuln_rule 'graphql_injection'. MASVS-CODE-4 (GraphQL Injection Prevention). Use when /hunt-mobile (via mhunt-dispatch) fires this rule's detection_pattern, or when hunting graphql injection in a decompiled app.
source: droid-llm-hunter (config/prompts/vuln_rules/graphql_injection.yaml)
masvs: MASVS-CODE-4
---

# mhunt-graphql-injection

port of droid-llm-hunter's `graphql_injection` vuln_rule into the `/hunt-mobile` model. **GraphQL Injection** — GraphQL query/mutation strings built by concatenating user input client-side, letting an attacker inject fields/args, alter the operation, or reach unauthorized data.

## MASVS

`MASVS-CODE-4` — GraphQL Injection Prevention. likely severity: **Medium** (confirm via the Gate-0 below; mobile severity depends on reachability + impact, not the pattern alone).

## Detection signal (the rule's `detection_pattern`)

android (smali/java/xml) — grep verbatim:

```
(?i)(graphql.*(query|mutation)|query.*=.*[\"']|mutation.*=.*[\"']|execute.*query)
```

ios parallel: GraphQL query strings built by `stringWithFormat:`/string interpolation before posting

a regex hit is a **lead, not a finding** — droid-llm-hunter then deep-scans it with the LLM. that deep-scan is the methodology below.

## Static methodology (deep scan)

- Find GraphQL operation strings assembled with `+`/format from user input rather than passed as `variables`.
- Injected fields can over-fetch (add `... on User { passwordHash }`) or change the mutation target.
- Also note the endpoint + auth header — feeds server-side GraphQL testing (introspection, IDOR on `node(id:)`).

## Dynamic confirmation

- Capture the request (Burp via proxy) and replay with injected fields / alias batching; run introspection if open.

device prereqs: rooted Android emulator/device with `adb` + `frida-server` (and `drozer`/`objection` where noted), or a jailbroken iOS device with `frida`/`objection`. no device -> report as a static-only lead, don't claim confirmed.

## PoC

```graphql
# injected via a concatenated variable that breaks out of the intended selection:
query { me { id } user(id:"VICTIM"){ email orders { total } } }
```

## Validation — MASVS Gate-0

before writing the report, answer all three:

1. **Reachability** — can an *external* actor trigger this (another app, a deep link, a network response, a shared file), or only the app itself? app-internal-only is usually not a finding.
2. **Impact** — what does the attacker gain (data read/write, code execution, auth bypass, privilege gain) and which CIA property does the victim lose? map to `MASVS-CODE-4`.
3. **Reproducible in 10 min** — exact entry point (component/URI/intent) + payload + observed result (leaked data / state change / execution), on a clean install, no pre-seeded state.

if any answer is weak, it's a static lead — keep hunting, don't file.

## Chains

client-side concat is the lead; the real money is server-side GraphQL IDOR — hand off to the web `hunt-graphql` skill if installed.
