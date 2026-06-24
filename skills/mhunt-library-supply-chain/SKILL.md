---
name: mhunt-library-supply-chain
description: Mobile hunting skill for library supply-chain audit on Android/iOS apps. Ported from droid-llm-hunter vuln_rule 'library_vulnerability'. MASVS-CODE-4 (Third-Party Library / Supply Chain Risk). Use when /hunt-mobile (via mhunt-dispatch) fires this rule's detection_pattern, or when hunting library supply-chain audit in a decompiled app.
source: droid-llm-hunter (config/prompts/vuln_rules/library_vulnerability.yaml)
masvs: MASVS-CODE-4
---

# mhunt-library-supply-chain

port of droid-llm-hunter's `library_vulnerability` vuln_rule into the `/hunt-mobile` model. **Library Supply-Chain Audit** — Third-party SDK / bundled library exhibits potentially-unwanted behavior or supply-chain risk: dynamic code loading (dropper), reflection to bypass API limits, native/command exec, device-identifier harvesting (spyware), or unsafe web bridges.

## MASVS

`MASVS-CODE-4` — Third-Party Library / Supply Chain Risk. likely severity: **High** (confirm via the Gate-0 below; mobile severity depends on reachability + impact, not the pattern alone).

## Detection signal (the rule's `detection_pattern`)

android (smali/java/xml) — grep verbatim:

```
DexClassLoader|PathClassLoader|URLClassLoader|Runtime\.exec|System\.loadLibrary|Method\.invoke|Class\.forName|getDeviceId|getSimSerialNumber|getSubscriberId|addJavascriptInterface
```

ios parallel: dynamic frameworks loading external code, `dlopen`, or SDKs harvesting `identifierForVendor`/contacts without need

a regex hit is a **lead, not a finding** — droid-llm-hunter then deep-scans it with the LLM. that deep-scan is the methodology below.

## Static methodology (deep scan)

- Treat 3rd-party packages as untrusted. Flag: `DexClassLoader`/`PathClassLoader`/`URLClassLoader` (loads code from external source = dropper risk).
- Reflection abuse (`Method.invoke`/`Class.forName`) to hide/bypass restricted API calls.
- `Runtime.exec()`/`System.loadLibrary()` running shell or hiding logic in native binaries.
- Surveillance: `getDeviceId`/`getSimSerialNumber`/`getSubscriberId`/location collected with no functional need.
- Unsafe `addJavascriptInterface` bridges in an SDK's WebView.

## Dynamic confirmation

- Frida-trace the suspect library: log `DexClassLoader` paths, `Runtime.exec` argv, outbound hosts; pcap to see what identifiers leave the device and where.

device prereqs: rooted Android emulator/device with `adb` + `frida-server` (and `drozer`/`objection` where noted), or a jailbroken iOS device with `frida`/`objection`. no device -> report as a static-only lead, don't claim confirmed.

## PoC

```bash
# enumerate dynamic loading + identifier harvesting across the decompiled tree:
grep -rEn 'DexClassLoader|Runtime\.exec|System\.loadLibrary|getDeviceId|getSubscriberId' jadx/sources/
# then frida-trace -U -i 'exec*' -i 'load*' -f com.target
```

## Validation — MASVS Gate-0

before writing the report, answer all three:

1. **Reachability** — can an *external* actor trigger this (another app, a deep link, a network response, a shared file), or only the app itself? app-internal-only is usually not a finding.
2. **Impact** — what does the attacker gain (data read/write, code execution, auth bypass, privilege gain) and which CIA property does the victim lose? map to `MASVS-CODE-4`.
3. **Reproducible in 10 min** — exact entry point (component/URI/intent) + payload + observed result (leaked data / state change / execution), on a clean install, no pre-seeded state.

if any answer is weak, it's a static lead — keep hunting, don't file.

## Chains

dynamic code loading + reflection -> RCE/dropper; identifier harvesting -> privacy/PII finding. cross-ref `mhunt-unsafe-reflection`, `mhunt-insecure-webview`.
