# Astra AV Engine

> **Part of the ASTRA Labs (Advanced Security Research and Analysis) series.**
> A transparent, open-source antivirus engine built in Go — designed to expose the internals of malware detection rather than hide behind a black box.

---

## Overview

Most antivirus engines are closed-source black boxes. You feed them a file, they return a verdict, and you have no idea why. The Astra AV Engine is different — it's built in the open, episode by episode, so you can follow along as detection techniques are added, improved, and eventually _bypassed_.

This project serves two purposes:

1. **Education** — understand how AV engines actually work under the hood.
2. **Red team research** — once the engine is built, we'll use it to demonstrate exactly how malware evades detection.

---

## Series Roadmap

| Episode | Feature                                            | Status      |
| ------- | -------------------------------------------------- | ----------- |
| 1       | Hash-based detection (MD5, SHA-1, SHA-256)         | ✅ Complete |
| 2       | YARA rule scanning                                 | 🔜 Planned  |
| 3       | String & API heuristics                            | 🔜 Planned  |
| 4       | PE header & section analysis                       | 🔜 Planned  |
| 5       | Entropy analysis (packed/encrypted file detection) | 🔜 Planned  |
| 6       | Fuzzy hashing (ssdeep/TLSH)                        | 🔜 Planned  |
| 7       | Malware evasion — defeating the engine             | 🔜 Planned  |

---

## Episode 1 — Hash-Based Detection

The first and most fundamental detection method: comparing a file's cryptographic hash against a database of known malware hashes.

### How it works

1. Compute the MD5, SHA-1, and SHA-256 hashes of the target file.
2. Look up each hash against a local signature database (a flat `.txt` file of known-bad hashes).
3. Return a `DETECTED` or `CLEAN` verdict with the matching hash type.

### Limitations (by design)

Hash-based detection is trivially bypassed — changing even a single byte produces a completely different hash. This is intentional. The malware evasion episode will demonstrate exactly this technique against our own engine.

---

## Project Structure

```
astra-av-engine/
├── main.go              # Entry point / CLI
├── scanner/
│   └── scanner.go       # Core scanning logic
├── signatures/
│   └── hashes.txt       # Known malware hash database
├── go.mod
└── README.md
```

---

## Getting Started

### Prerequisites

- Go 1.21+

### Clone & Build

```bash
git clone https://github.com/ASTRA-LabsHQ/Astra-Av-Engine.git
cd Astra-Av-Engine
go build -o astra-av ./...
```

### Usage

**Scan a single file:**

```bash
./astra-av scan --file /path/to/suspicious.exe
```

**Scan a directory:**

```bash
./astra-av scan --dir /path/to/directory
```

**Add a hash to the signature database:**

```bash
./astra-av add-hash --hash <sha256> --name "WannaCry Ransomware"
```

### Example Output

```
[*] Astra AV Engine v0.1.0
[*] Scanning: wannacry.exe

[!] DETECTED — wannacry.exe
    SHA-256 : db349b97c37d22f5ea1d1841e3c89eb4ed9fde70b8c7046e6b8f4...
    Match   : WannaCry Ransomware
    Verdict : MALICIOUS
```

---

## Signature Database

Hashes are stored in `signatures/hashes.txt` in a simple pipe-delimited format:

```
SHA256|db349b97c37d22f5ea1d1841e3c89eb4ed9fde70b8c7046e6b8f4...|WannaCry Ransomware
MD5|84c82835a5d21bbcf75a61706d8ab549|WannaCry Ransomware
SHA1|4da1f312a214c07143abeeafb695d904440a420a|WannaCry Ransomware
```

You can populate this with hashes from:

- [MalwareBazaar](https://bazaar.abuse.ch/)
- [VirusTotal](https://www.virustotal.com/)
- [Hybrid Analysis](https://www.hybrid-analysis.com/)

---

## Disclaimer

This project is intended for **educational and research purposes only**. Do not use this tool on systems or files you do not own or have explicit permission to analyze. All malware samples referenced in this project are handled in isolated lab environments.

---

## About ASTRA Labs

ASTRA Labs (Advanced Security Research and Analysis) is an open-source cybersecurity research and education project covering threat intelligence, malware analysis, and defensive tooling.

- GitHub: [ASTRA-LabsHQ](https://github.com/ASTRA-LabsHQ)
