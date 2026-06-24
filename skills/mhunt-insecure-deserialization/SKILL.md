---
name: mhunt-insecure-deserialization
description: Mobile hunting skill for insecure deserialization on Android/iOS apps. Ported from droid-llm-hunter vuln_rule 'insecure_deserialization'. MASVS-CODE-4 (Insecure Deserialization). Use when /hunt-mobile (via mhunt-dispatch) fires this rule's detection_pattern, or when hunting insecure deserialization in a decompiled app.
source: droid-llm-hunter (config/prompts/vuln_rules/insecure_deserialization.yaml)
masvs: MASVS-CODE-4
---

# mhunt-insecure-deserialization

port of droid-llm-hunter's `insecure_deserialization` vuln_rule into the `/hunt-mobile` model. **Insecure Deserialization** — `ObjectInputStream.readObject()` on data from an untrusted source (Intent `getSerializableExtra`, network, disk) without look-ahead class validation -> object injection / RCE when a gadget chain is present.

## MASVS

`MASVS-CODE-4` — Insecure Deserialization. likely severity: **High** (confirm via the Gate-0 below; mobile severity depends on reachability + impact, not the pattern alone).

## Detection signal (the rule's `detection_pattern`)

android (smali/java/xml) — grep verbatim:

```
ObjectInputStream.*\.readObject
```

ios parallel: `NSKeyedUnarchiver unarchiveObjectWithData:` without `requiresSecureCoding`/`decodeObjectOfClass:`

a regex hit is a **lead, not a finding** — droid-llm-hunter then deep-scans it with the LLM. that deep-scan is the methodology below.

## Static methodology (deep scan)

- Find `readObject()` and trace the stream source. Tainted if it derives from `getSerializableExtra`/`getParcelableExtra`, a socket, or a file an attacker controls.
- No `ObjectInputFilter`/look-ahead class allow-list = vulnerable to gadget chains in the app's dependency set.
- Parcelable mis-handling (reading type from the parcel) is the mobile-native variant.

## Dynamic confirmation

- Deliver a serialized payload through the exported entry point (`--es`/extra Serializable) and observe behavior; with a known gadget, confirm execution.

device prereqs: rooted Android emulator/device with `adb` + `frida-server` (and `drozer`/`objection` where noted), or a jailbroken iOS device with `frida`/`objection`. no device -> report as a static-only lead, don't claim confirmed.

## PoC

```java
// exported activity does: (Foo) getIntent().getSerializableExtra("data") -> readObject path
Intent i = new Intent();
i.setClassName("com.target","com.target.ImportActivity");
i.putExtra("data", craftedGadgetSerializable);   // ysoserial-style gadget if present
startActivity(i);
```

## Validation — MASVS Gate-0

before writing the report, answer all three:

1. **Reachability** — can an *external* actor trigger this (another app, a deep link, a network response, a shared file), or only the app itself? app-internal-only is usually not a finding.
2. **Impact** — what does the attacker gain (data read/write, code execution, auth bypass, privilege gain) and which CIA property does the victim lose? map to `MASVS-CODE-4`.
3. **Reproducible in 10 min** — exact entry point (component/URI/intent) + payload + observed result (leaked data / state change / execution), on a clean install, no pre-seeded state.

if any answer is weak, it's a static lead — keep hunting, don't file.

## Chains

deserialization RCE is terminal on its own; reachability via `mhunt-exported-components` is the precondition.
