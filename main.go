package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ASTRA-LabsHQ/Astra-AV-Engine/scanner"
)

// ============================================================
// ASTRA AV Engine — Episode 1: Hash-Based Detection
// main.go — CLI entry point
// ============================================================

const version = "0.1.0"

// defaultSigDB returns the path to the signature database relative to the binary.
func defaultSigDB() string {
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join("signatures", "hashes.txt")
	}
	return filepath.Join(filepath.Dir(exe), "signatures", "hashes.txt")
}

func printBanner() {
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("  Astra AV Engine v%s\n", version)
	fmt.Println("  Advanced Security Research and Analysis")
	fmt.Println("  Detection: MD5 / SHA-1 / SHA-256 Hash Signatures")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()
}

func printResult(r scanner.ScanResult) {
	if r.Error != nil {
		fmt.Printf("  [ERR]     %s\n            %v\n\n", r.FilePath, r.Error)
		return
	}

	if r.Detected {
		fmt.Println("  [!] DETECTED —", r.FilePath)
		fmt.Printf("      %-10s: %s\n", r.MatchType, r.MatchHash)
		fmt.Printf("      %-10s: %s\n", "Match", r.ThreatName)
		fmt.Printf("      %-10s: %s\n", "Verdict", r.Verdict)
		fmt.Printf("      %-10s: %s\n\n", "Scan time", r.ScanTime)
	} else {
		fmt.Printf("  [CLEAN]   %s\n", r.FilePath)
	}
}

func printSummary(results []scanner.ScanResult, elapsed time.Duration) {
	total, detected, errors := 0, 0, 0
	for _, r := range results {
		total++
		if r.Detected {
			detected++
		}
		if r.Error != nil {
			errors++
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("  Scan complete     : %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("  Files scanned     : %d\n", total)
	fmt.Printf("  Threats detected  : %d\n", detected)
	fmt.Printf("  Errors            : %d\n", errors)
	fmt.Println(strings.Repeat("-", 60))

	if detected > 0 {
		fmt.Println("\n  *** THREATS DETECTED — DO NOT EXECUTE FLAGGED FILES ***")
	} else {
		fmt.Println("\n  No threats detected.")
	}
}

func main() {
	printBanner()

	// ── Subcommands ──────────────────────────────────────────
	scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
	scanFile := scanCmd.String("file", "", "Path to a single file to scan")
	scanDir := scanCmd.String("dir", "", "Path to a directory to scan recursively")
	scanDB := scanCmd.String("db", defaultSigDB(), "Path to signature database")

	addCmd := flag.NewFlagSet("add-hash", flag.ExitOnError)
	addHash := addCmd.String("hash", "", "Hash value to add")
	addType := addCmd.String("type", "SHA256", "Hash type: MD5, SHA1, or SHA256")
	addName := addCmd.String("name", "", "Threat name (e.g. \"WannaCry Ransomware\")")
	addDB := addCmd.String("db", defaultSigDB(), "Path to signature database")

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage:")
		fmt.Fprintln(os.Stderr, "  astra-av scan  --file <path>")
		fmt.Fprintln(os.Stderr, "  astra-av scan  --dir  <path>")
		fmt.Fprintln(os.Stderr, "  astra-av add-hash --hash <hash> --name <threat>")
		os.Exit(1)
	}

	switch os.Args[1] {

	// ── scan ─────────────────────────────────────────────────
	case "scan":
		scanCmd.Parse(os.Args[2:])

		if *scanFile == "" && *scanDir == "" {
			fmt.Fprintln(os.Stderr, "[ERROR] Provide --file or --dir")
			scanCmd.Usage()
			os.Exit(1)
		}

		db, err := scanner.LoadSignatures(*scanDB)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] Loaded %d signatures from %s\n\n", db.Count(), *scanDB)

		start := time.Now()
		var results []scanner.ScanResult

		if *scanFile != "" {
			fmt.Printf("[*] Scanning file: %s\n\n", *scanFile)
			results = append(results, scanner.ScanFile(*scanFile, db))
		} else {
			fmt.Printf("[*] Scanning directory: %s\n\n", *scanDir)
			results = scanner.ScanDirectory(*scanDir, db)
		}

		for _, r := range results {
			printResult(r)
		}
		printSummary(results, time.Since(start))

	// ── add-hash ─────────────────────────────────────────────
	case "add-hash":
		addCmd.Parse(os.Args[2:])

		if *addHash == "" || *addName == "" {
			fmt.Fprintln(os.Stderr, "[ERROR] --hash and --name are required")
			addCmd.Usage()
			os.Exit(1)
		}

		validTypes := map[string]bool{"MD5": true, "SHA1": true, "SHA256": true}
		hashType := strings.ToUpper(*addType)
		if !validTypes[hashType] {
			fmt.Fprintf(os.Stderr, "[ERROR] Invalid hash type %q — must be MD5, SHA1, or SHA256\n", *addType)
			os.Exit(1)
		}

		if err := scanner.AddSignature(*addDB, hashType, *addHash, *addName); err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] Added signature: %s|%s|%s\n", hashType, *addHash, *addName)

	default:
		fmt.Fprintf(os.Stderr, "[ERROR] Unknown command %q\n", os.Args[1])
		fmt.Fprintln(os.Stderr, "Commands: scan, add-hash")
		os.Exit(1)
	}
}
