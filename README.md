# 📱 Claude-MobileHunter (`/hunt-mobile`)

Mobile-app vulnerability hunting for **[Claude Code](https://claude.com/claude-code)**.

`/hunt-mobile` decompiles an Android **APK** (or iOS **IPA**), runs an LLM-assisted SAST
pipeline, and automatically loads the right hunting skills for the vulnerability classes it
finds. It is a faithful port of **[droid-llm-hunter](https://github.com/roomkangali/droid-llm-hunter)**'s
26 `vuln_rules` into the Claude Code *skill* model — extended with iOS parallels, runtime
(dynamic) confirmation steps, and an OWASP **MASVS** validation gate per finding.

> ⚠️ **Authorized testing only.** Use this on apps you own or are explicitly authorized to test
> (bug-bounty scope, pentest SOW, CTF, your own builds). You are responsible for staying in scope.

---

## What you get

| Component | Count | Role |
|---|---|---|
| `/hunt-mobile` command | 1 | Dispatcher — parses the target, settles platform + filter mode, hands off |
| `mhunt-dispatch` skill | 1 | Pipeline orchestrator: decompile → scope filter → risk-identify → load skills → taxonomy |
| `mhunt-*` vuln skills | 26 | One per droid-llm-hunter rule; each carries its `detection_pattern`, methodology, PoC, MASVS gate |

The pipeline mirrors droid-llm-hunter end-to-end:

```
decompile  ->  scope filter  ->  risk identify  ->  deep scan  ->  global context  ->  exploit  ->  MASVS report
(apktool/jadx)  (drop noise)   (grep detection_   (LLM reasons   (chain shared    (PoC)      (per-skill
                                patterns)          per rule)      sources)                    Gate-0)
```

### The 26 vulnerability classes (MASVS-mapped)

`sql-injection` · `webview-xss` · `insecure-webview` · `webview-file-access` · `webview-deeplink` ·
`deeplink-hijack` · `deeplink-logic-bypass` · `hardcoded-secrets` · `hardcoded-secrets-xml` ·
`insecure-storage` · `insecure-file-permissions` · `insecure-random` · `biometric-bypass` ·
`exported-components` · `intent-spoofing` · `pending-intent-hijacking` · `fragment-injection` ·
`path-traversal` · `zip-slip` · `graphql-injection` · `unsafe-reflection` · `insecure-deserialization` ·
`jetpack-compose` · `strandhogg` · `library-supply-chain` · `universal-logic-flaw`

---

## Install (Claude Code plugin — recommended)

Inside Claude Code:

```
/plugin marketplace add aliothme/Claude-MobileHunter
/plugin install hunt-mobile@claude-mobilehunter
```

That's it — `/hunt-mobile` and all 26 `mhunt-*` skills are now available. Update later with
`/plugin marketplace update claude-mobilehunter`.

### Install (manual)

If you'd rather copy the files into your user config:

```bash
git clone https://github.com/aliothme/Claude-MobileHunter.git
cd Claude-MobileHunter
./install.sh            # copies command + skills into ~/.claude/
```

Uninstall: `./install.sh --uninstall`.

---

## Usage

```
/hunt-mobile app.apk                          # Android, hybrid mode (default)
/hunt-mobile app.ipa --platform ios           # iOS
/hunt-mobile app.apk --mode static            # SAST only, no device needed
/hunt-mobile com.target.app                    # installed package (pulled via adb first)
/hunt-mobile app.apk --vuln-class webview-xss  # load only one skill, skip triage
```

**Filter modes** (`--mode`):

- `static` — decompile + signal grep + deep-scan. No device required. Great for triage/CI.
- `dynamic` — runtime exploitation only (assumes you know the sinks).
- `hybrid` *(default)* — static finds the sink, dynamic proves it. Highest signal.

### Tooling

**Static** (required): [`apktool`](https://apktool.org/), [`jadx`](https://github.com/skylot/jadx), `unzip`, `aapt`.
For iOS: `unzip`, `plutil`, `class-dump` (and optionally Hopper/Ghidra).

**Dynamic** (optional — only for `--mode dynamic`/`hybrid`): a rooted Android emulator/device with
[`adb`](https://developer.android.com/tools/adb) + [`frida-server`](https://frida.re/),
[`drozer`](https://github.com/WithSecureLabs/drozer), [`objection`](https://github.com/sensepost/objection);
or a jailbroken iOS device with `frida`/`objection`. If no device is connected, `/hunt-mobile`
falls back to `static` and tells you — it never silently skips the runtime step.

---

## How a finding is reported

Every `mhunt-*` skill ends with a **MASVS Gate-0** (reachability → impact → 10-minute repro). A regex
hit is a *lead*, not a finding; the skill's deep-scan + the Gate-0 are what turn it into a report.

---

## Credits & license

This project ports the vulnerability rules and analysis flow of
**[droid-llm-hunter](https://github.com/roomkangali/droid-llm-hunter)** by **Kang Ali** (MIT).
Full attribution in [CREDITS.md](CREDITS.md). The original `vuln_rules` `detection_pattern` regexes
and MASVS mappings are preserved; methodology, iOS parallels, dynamic steps, and the Claude Code
packaging are added here.

Licensed under the [MIT License](LICENSE). Not affiliated with Anthropic.
