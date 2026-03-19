Astra AV Engine

Part of the ASTRA Labs (Advanced Security Research and Analysis) series.
A transparent, open-source antivirus engine built in Go — designed to expose the internals of malware detection rather than hide behind a black box.

Overview
Most antivirus engines are closed-source black boxes. You feed them a file, they return a verdict, and you have no idea why. The Astra AV Engine is different — it's built in the open, episode by episode, so you can follow along as detection techniques are added, improved, and eventually bypassed.
This project serves two purposes:

Education — understand how AV engines actually work under the hood.
Red team research — once the engine is built, we'll use it to demonstrate exactly how malware evades detection.

Series Roadmap
EpisodeFeatureStatus1Hash-based detection (MD5, SHA-1, SHA-256)✅ Complete2YARA rule scanning✅ Complete3String & API heuristics🔜 Planned4PE header & section analysis🔜 Planned5Entropy analysis (packed/encrypted file detection)🔜 Planned6Fuzzy hashing (ssdeep/TLSH)🔜 Planned7Malware evasion — defeating the engine🔜 Planned

Episode 2 — YARA Rule Scanning
YARA is the industry-standard pattern matching language for malware research. Where hash detection requires an exact known-bad hash, YARA lets you write flexible rules that match on strings, byte patterns, API imports, file structure, and more — making it far more powerful against unknown or slightly modified samples.
How it works

YARA rules (.yar / .yara files) are loaded and compiled into a single ruleset at startup.
Each file is scanned against the compiled ruleset.
Any matching rules are reported with the rule name, namespace, tags, and the specific matched strings and their offsets within the file.
YARA scanning runs alongside hash detection — a file can trigger both.

Prerequisites
YARA scanning requires libyara to be installed on your system, as go-yara is a CGo binding.
Linux (Debian/Ubuntu):
sudo apt install libyara-dev
macOS:
brew install yara
Windows:
Download the YARA release from https://github.com/VirusTotal/yara/releases and follow the build instructions for CGo on Windows.
Dependency
go get github.com/hillu/go-yara/v4
Usage
Pass a single .yar / .yara file or a directory of rule files via --rules:

# Scan a file with YARA rules from a directory

./astra-av scan --file /path/to/suspicious.exe --rules ./rules

# Scan a file with a single rule file

./astra-av scan --file /path/to/suspicious.exe --rules ./rules/malware_generic.yar

# Hash-only scan (YARA is optional — omit --rules to disable)

./astra-av scan --file /path/to/suspicious.exe
Example Output
============================================================
Astra AV Engine v0.2.0
Advanced Security Research and Analysis
Detection: Hash Signatures + YARA Rules
============================================================

[*] Loaded 3 hash signatures from signatures/hashes.txt
[*] Loaded 1 YARA rule file(s) from rules/

[*] Scanning file: malware_sample.exe

[!] DETECTED (YARA) — malware_sample.exe
Verdict : MALICIOUS
[YARA] malware_generic::Suspicious_Process_Injection_APIs [injection]
$api1 @ 0x3a20 : "VirtualAllocEx"
$api2 @ 0x3a34 : "WriteProcessMemory"
$api3 @ 0x3a50 : "CreateRemoteThread"
[YARA] malware_generic::Suspicious_Registry_Persistence
$reg1 @ 0x5c10 : "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Scan time : 12ms

---

Scan complete : 12ms
Files scanned : 1
Hash detections : 0
YARA detections : 1
Errors : 0

---

**_ THREATS DETECTED — DO NOT EXECUTE FLAGGED FILES _**
Rules Directory
Place your .yar or .yara files in the rules/ directory. The engine will compile all of them into a single ruleset at startup. A sample ruleset is included covering:

PowerShell download cradles
Process injection API imports
Registry persistence keys
Base64-encoded PE headers
Ransomware file targeting patterns

For production-quality rules, pull from:

Yara-Rules/rules
Neo23x0/signature-base
MalwareBazaar YARA export

Limitations (by design)
YARA rules are only as good as what they cover. A malware author who knows your ruleset can trivially rename strings, encrypt payloads, or restructure code to evade them. The evasion episode will demonstrate exactly this against our own rules.

Episode 1 — Hash-Based Detection
The first and most fundamental detection method: comparing a file's cryptographic hash against a database of known malware hashes.
How it works

Compute the MD5, SHA-1, and SHA-256 hashes of the target file.
Look up each hash against a local signature database (a flat .txt file of known-bad hashes).
Return a DETECTED or CLEAN verdict with the matching hash type.

Limitations (by design)
Hash-based detection is trivially bypassed — changing even a single byte produces a completely different hash. This is intentional. The malware evasion episode will demonstrate exactly this technique against our own engine.

Project Structure
astra-av-engine/
├── main.go # Entry point / CLI
├── scanner/
│ ├── scanner.go # Core scanning logic (hash detection)
│ └── yara.go # YARA rule loading and scanning
├── signatures/
│ └── hashes.txt # Known malware hash database
├── rules/
│ └── malware_generic.yar # Sample YARA rules
│ └── signatures.txt # Known malware hash database
├── go.mod
└── README.md

Getting Started
Prerequisites

Go 1.21+
libyara (for YARA scanning — see Episode 2 prerequisites above)

Clone & Build
git clone https://github.com/ASTRA-LabsHQ/Astra-Av-Engine.git
cd Astra-Av-Engine
go build -o astra-av ./...
Usage
Scan a single file (hash only):
./astra-av scan --file /path/to/suspicious.exe
Scan a single file (hash + YARA):
./astra-av scan --file /path/to/suspicious.exe --rules ./rules
Scan a directory:
./astra-av scan --dir /path/to/directory --rules ./rules
Add a hash to the signature database:
./astra-av add-hash --hash <sha256> --name "WannaCry Ransomware"

Signature Database
Hashes are stored in signatures/hashes.txt in a simple pipe-delimited format:

```

### Example Output

```

[*] Astra AV Engine v0.1.0
[*] Scanning: wannacry.exe

[!] DETECTED — wannacry.exe
SHA-256 : db349b97c37d22f5ea1d1841e3c89eb4ed9fde70b8c7046e6b8f4...
Match : WannaCry Ransomware
Verdict : MALICIOUS

```

---

## Signature Database

Hashes are stored in `signatures/signatures.txt` in a simple pipe-delimited format:

```

SHA256|db349b97c37d22f5ea1d1841e3c89eb4ed9fde70b8c7046e6b8f4...|WannaCry Ransomware
MD5|84c82835a5d21bbcf75a61706d8ab549|WannaCry Ransomware
SHA1|4da1f312a214c07143abeeafb695d904440a420a|WannaCry Ransomware
You can populate this with hashes from:

MalwareBazaar
VirusTotal
Hybrid Analysis

Disclaimer
This project is intended for educational and research purposes only. Do not use this tool on systems or files you do not own or have explicit permission to analyze. All malware samples referenced in this project are handled in isolated lab environments.

About ASTRA Labs
ASTRA Labs (Advanced Security Research and Analysis) is an open-source cybersecurity research and education project covering threat intelligence, malware analysis, and defensive tooling.

GitHub: ASTRA-LabsHQ
