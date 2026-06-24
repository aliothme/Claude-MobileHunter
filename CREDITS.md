# Credits & Attribution

## Upstream: droid-llm-hunter

This project is a port of **[droid-llm-hunter](https://github.com/roomkangali/droid-llm-hunter)**
by **Kang Ali** ([@roomkangali](https://github.com/roomkangali)), licensed under the MIT License.

What is derived from droid-llm-hunter:

- The **26 vulnerability rules** — their `detection_pattern` regexes, names, and the analysis
  intent of each rule prompt (`config/prompts/vuln_rules/*.yaml`).
- The **OWASP MASVS mappings** (`config/knowledge_base/masvs_mapping.json`).
- The **analysis pipeline** design: decompile → scope filter → risk identification →
  deep scan → global context → exploit → report.

What is original to Claude-MobileHunter:

- Repackaging each rule as a Claude Code **skill** (`SKILL.md`) with hunting methodology.
- **iOS parallels** for each class (droid-llm-hunter is Android-only).
- **Dynamic / runtime confirmation** steps (adb, drozer, objection, Frida).
- A per-skill **MASVS Gate-0** validation checklist.
- The `/hunt-mobile` command and `mhunt-dispatch` orchestrator that wire it into Claude Code.

### Upstream license (preserved per MIT terms)

```
MIT License

Copyright (c) 2026 Kang Ali

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

If you use this project, please also star and credit the upstream
[droid-llm-hunter](https://github.com/roomkangali/droid-llm-hunter).

## Tools referenced by the skills

apktool · jadx · aapt · dex2jar · adb · Frida · objection · drozer · class-dump — each under its own license.
