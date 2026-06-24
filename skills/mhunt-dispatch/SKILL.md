---
name: mhunt-dispatch
description: Pipeline orchestrator + skill-set loader for /hunt-mobile. Reproduces droid-llm-hunter's analysis flow (decompile, scope filter, risk identification, deep scan, global context, exploit, report) over an APK/IPA, greps every vuln_rule detection_pattern to decide which mhunt-* skills to load, and prints the taxonomy. Use when /hunt-mobile has parsed a target and settled platform + filter mode. Not for direct user invocation.
---

# mhunt-dispatch

pipeline orchestrator for `/hunt-mobile`. one concept (decompile → triage → load the right `mhunt-*` skills), one place. this is the `dlh.py` core of droid-llm-hunter, expressed as a Claude skill.

invocation contract:

```
mhunt-dispatch platform=android mode=hybrid target=<path-or-package>
mhunt-dispatch platform=ios     mode=static target=<path>
mhunt-dispatch ... vuln-class=webview-xss      # skip triage, load one skill
```

## the pipeline (droid-llm-hunter parity)

```
1 decompile          APK/IPA -> source tree
2 scope filter       drop noise (R.java, generated, known-good libs unless mode targets libs)
3 risk identify      grep every rule detection_pattern -> set of FIRED rules
4 deep scan          load the matched mhunt-* skills; each reasons over its hits (the rule prompt)
5 global context     cross-reference: which fired sinks share a source (Intent/deeplink/export)
6 exploit            per-skill PoC; compose chains
7 report             MASVS-mapped findings
```

steps 1-3 run here. step 4 loads skills and returns control to `/hunt-mobile`. steps 5-7 are driven by the loaded skills + `/chain` + `/report`.

## step 1 — decompile

work in a `.gitignore`d scratch dir. never commit extracted app contents.

### android

```bash
APP="$TARGET"; OUT="mobile/$(basename "$APP" .apk)"
mkdir -p "$OUT"
# if a package name, not a file: pull it first
# adb shell pm path <pkg>  ->  adb pull <path> "$APP"
apktool d -f -o "$OUT/apktool" "$APP"          # manifest + smali + resources
jadx -d "$OUT/jadx" "$APP" 2>/dev/null || true  # readable java (best-effort)
unzip -o -q "$APP" -d "$OUT/raw"                # raw assets, libs, classes.dex
SRC="$OUT"   # grep target = whole tree (smali + java + xml + assets)
```

key files: `$OUT/apktool/AndroidManifest.xml`, `$OUT/apktool/res/values/strings.xml`, `$OUT/jadx/sources/`, `$OUT/raw/assets/`, `$OUT/raw/lib/`.

### ios

```bash
APP="$TARGET"; OUT="mobile/$(basename "$APP" .ipa)"
mkdir -p "$OUT"; unzip -o -q "$APP" -d "$OUT/raw"
APPDIR=$(echo "$OUT"/raw/Payload/*.app)
# Info.plist (convert binary plist), entitlements, Mach-O class metadata
plutil -convert xml1 -o "$OUT/Info.plist" "$APPDIR/Info.plist" 2>/dev/null || true
class-dump -H "$APPDIR" -o "$OUT/headers" 2>/dev/null || true   # if not Swift-stripped
SRC="$OUT"
```

key files: `$OUT/Info.plist` (URL schemes, ATS, `NSAppTransportSecurity`), `$APPDIR/embedded.mobileprovision`, `$OUT/headers/`, the Mach-O binary itself (`strings`, `otool -L`).

## step 2 — scope filter

drop generated/no-signal files before the grep so the risk pass stays cheap:

```bash
# android: skip R$*, BuildConfig, known SDK packages unless mode=library audit
FILTER='-path */R.java -o -path */R$*.smali -o -path */BuildConfig*'
# ios: skip Pods headers and system frameworks
```

if `mode` targets libraries / supply chain, do NOT filter third-party packages — that is where `mhunt-library-supply-chain` hunts.

## step 3 — risk identification (the detection_pattern grep)

this is droid-llm-hunter's `identify_risk_prompt` stage made concrete: grep each rule's `detection_pattern` over `$SRC`; a hit means that rule FIRED and its skill should load. run them all in one pass:

```bash
cd "$SRC"
echo "=== android rule grep ==="
grep -rREn --include=*.smali --include=*.java --include=*.xml \
  -e 'rawQuery|execSQL' \                                   # sql-injection
  -e 'setJavaScriptEnabled\(true\)|addJavascriptInterface' \ # webview-xss / insecure-webview
  -e 'setAllow(File|Universal)Access(FromFileURLs)?\s*\(?\s*true' \ # webview-file-access
  -e 'android\.intent\.action\.VIEW' \                       # webview-deeplink / deeplink-hijack
  -e 'android:autoVerify|android:scheme' \                   # deeplink-hijack
  -e '\.getQueryParameter|Uri\.parse' \                      # deeplink-logic-bypass
  -e 'AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|(api_key|password|secret|token).*=.*["'"'"']' \ # hardcoded-secrets
  -e 'getSharedPreferences|MODE_WORLD_READABLE|MODE_WORLD_WRITABLE' \ # insecure-storage / file-perms
  -e 'Ljava/util/Random;|new Random\(' \                     # insecure-random
  -e 'BiometricPrompt' \                                     # biometric-bypass
  -e 'android:exported=["'"'"']true["'"'"']' \               # exported-components / intent-spoofing
  -e 'PendingIntent\.(getActivity|getService|getBroadcast)' \ # pending-intent-hijacking
  -e 'Landroid/preference/PreferenceActivity;' \             # fragment-injection
  -e 'openFile' \                                            # path-traversal
  -e 'ZipEntry.*\.getName' \                                 # zip-slip
  -e 'graphql.*(query|mutation)|execute.*query' \            # graphql-injection
  -e 'Class\.forName|Method\.invoke|ClassLoader\.loadClass' \ # unsafe-reflection
  -e 'ObjectInputStream.*\.readObject' \                     # insecure-deserialization
  -e '@Composable' \                                         # jetpack-compose
  -e 'singleTask' \                                          # strandhogg (+ confirm taskAffinity/exported in manifest)
  -e 'DexClassLoader|PathClassLoader|URLClassLoader|Runtime\.exec|System\.loadLibrary' \ # library-supply-chain
  . 2>/dev/null | sed 's/:.*//' | sort | uniq -c | sort -rn | head -60
```

ios analogues (grep `$OUT/headers`, `Info.plist`, and `strings` on the Mach-O): `stringWithFormat:.*SELECT` (sql), `UIWebView|WKWebView .* evaluateJavaScript|JSContext` (webview), `CFURLSchemes`/`CFBundleURLSchemes` (deeplink), `kSecAttrAccessible` + `NSUserDefaults` storing secrets (storage), `arc4random`/`rand()` vs `SecRandomCopyBytes` (random), `LAContext .* evaluatePolicy` (biometric), `NSKeyedUnarchiver` without secure coding (deserialization), `application:openURL:`/`continueUserActivity:` (deeplink-logic), hardcoded keys in `Info.plist`/binary `strings`.

record, per fired rule, the file:line list — that is the input the matched skill deep-scans in step 4.

## step 4 — load the matched skill set

map each fired rule → skill, invoke via the Skill tool. if `vuln-class=X` was passed, load only `mhunt-X` and skip the rest.

```
rule fired                        skill
--------------------------------- ----------------------------
rawQuery/execSQL                  mhunt-sql-injection
setJavaScriptEnabled/JS-iface     mhunt-webview-xss
addJavascriptInterface+fileURLs   mhunt-insecure-webview
setAllow*Access...true            mhunt-webview-file-access
VIEW intent + WebView activity    mhunt-webview-deeplink
autoVerify/scheme, no host        mhunt-deeplink-hijack
getQueryParameter/Uri.parse       mhunt-deeplink-logic-bypass
AIza/AKIA/secret=                 mhunt-hardcoded-secrets
strings.xml secret resource       mhunt-hardcoded-secrets-xml
getSharedPreferences/WORLD_*      mhunt-insecure-storage
openFileOutput + WORLD_*          mhunt-insecure-file-permissions
java.util.Random                  mhunt-insecure-random
BiometricPrompt                   mhunt-biometric-bypass
exported=true (no permission)     mhunt-exported-components
exported=true (action sink)       mhunt-intent-spoofing
PendingIntent.get* + MUTABLE      mhunt-pending-intent-hijacking
extends PreferenceActivity        mhunt-fragment-injection
ContentProvider.openFile          mhunt-path-traversal
ZipEntry.getName, no canonical    mhunt-zip-slip
graphql query concat              mhunt-graphql-injection
Class.forName/Method.invoke       mhunt-unsafe-reflection
ObjectInputStream.readObject      mhunt-insecure-deserialization
@Composable + no FLAG_SECURE      mhunt-jetpack-compose
singleTask + exported + affinity  mhunt-strandhogg
DexClassLoader/Runtime.exec/...   mhunt-library-supply-chain
(always loaded)                   mhunt-universal-logic-flaw
```

### load budget — cap at 8

real apps fire 15+ rules. loading all 26 skills blows the context window. apply MASVS-severity precedence and cap loaded skills at 8 (plus `mhunt-universal-logic-flaw`, always on, as the conceptual backstop). print the rest under `deferred:`.

```
tier 1  code-execution / RCE   mhunt-insecure-deserialization, mhunt-unsafe-reflection,
        (highest blast radius)  mhunt-fragment-injection, mhunt-library-supply-chain
tier 2  injection / data theft mhunt-sql-injection, mhunt-webview-xss, mhunt-insecure-webview,
                                mhunt-webview-file-access, mhunt-path-traversal, mhunt-zip-slip,
                                mhunt-graphql-injection
tier 3  auth / IPC / hijack    mhunt-biometric-bypass, mhunt-intent-spoofing,
                                mhunt-exported-components, mhunt-pending-intent-hijacking,
                                mhunt-deeplink-hijack, mhunt-deeplink-logic-bypass, mhunt-strandhogg
tier 4  storage / crypto / leak mhunt-hardcoded-secrets, mhunt-hardcoded-secrets-xml,
                                mhunt-insecure-storage, mhunt-insecure-file-permissions,
                                mhunt-insecure-random, mhunt-jetpack-compose
```

load highest-tier first; stop at 8. always also load `mhunt-universal-logic-flaw` (it does not count against the 8 — it is the cross-cutting logic/IPC/business reasoner, droid-llm-hunter's `universal_logic_flaw` rule).

## step 5 — taxonomy print (once)

emit a deterministic block. plain text, lowercase, colon-delimited.

```
loaded for mobile hunt ({android|ios}, mode={static|dynamic|hybrid}): {N} skills
  decompiled:  {OUT path}
  fired:       {count} rules
  rce:         {tier-1 skills that fired}
  inj:         {tier-2}
  ipc:         {tier-3}
  storage:     {tier-4}
  logic:       mhunt-universal-logic-flaw
  deferred:    {fired-but-past-the-8-cap skills, or omit line if none}
  device:      {connected | none — static only}
```

## step 6 — return control to /hunt-mobile

after the taxonomy print, hand control back to `/hunt-mobile` step 4 (active testing). do not run probes here — this skill only decompiles, triages, and loads context.

## privacy

never echo or persist SOW / engagement-letter content. decompiled source, extracted assets, and harvested secrets stay in the `.gitignore`d `mobile/` scratch dir. redact any secret to first/last 4 chars before it appears in a report.

---

## Related Skills & Chains

- **all 26 `mhunt-*` skills** — this skill is the loader; it greps detection_patterns and invokes the matched skills, which carry the actual methodology, PoC, and MASVS gate.
- **`mhunt-universal-logic-flaw`** — always loaded; the conceptual backstop for IPC / reflection / deserialization / business-logic chains that the pattern-based rules miss.
- **`/chain`** (web /hunt suite, if installed) — when a mobile primitive (e.g. exported-component write + insecure-storage read) composes into a higher-severity finding.
