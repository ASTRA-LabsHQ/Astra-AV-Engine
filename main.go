package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ASTRA-LabsHQ/Astra-Av-Engine/scanner"
)

const version = "0.1.0"
const sigDB = "signatures/hashes.txt"

const banner = `
  ___        _             
 / _ \      | |           
/ /_\ \  ___| |_ _ __ __ _
|  _  |/ __| __| '__/ _' |
| | | |\__ \ |_| | | (_| |
\_| |_/|___/\__|_|  \__,_|
 
  Astra AV Engine v%s — Advanced Security Research and Analysis
  github.com/ASTRA-LabsHQ/Astra-Av-Engine
`

func main() {
	fmt.Printf(banner, version)

	// Subcommands
	scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
	addHashCmd := flag.NewFlagSet("add-hash", flag.ExitOnError)

	// scan flags
	scanFile := scanCmd.String("file", "", "Path to a file to scan")
	scanDir := scanCmd.String("dir", "", "Path to a directory to scan")

	// add-hash flags
	addHashValue := addHashCmd.String("hash", "", "Hash value to add")
	addHashName := addHashCmd.String("name", "", "Malware name/label for this hash")
	addHashType := addHashCmd.String("type", "SHA256", "Hash type: MD5, SHA1, or SHA256 (default: SHA256)")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		scanCmd.Parse(os.Args[2:])
		runScan(*scanFile, *scanDir)
	case "add-hash":
		addHashCmd.Parse(os.Args[2:])
		runAddHash(*addHashValue, *addHashName, *addHashType)
	default:
		printUsage()
		os.Exit(1)
	}
}

func runScan(file, dir string) {
	if file == "" && dir == "" {
		fmt.Println("[!] Error: provide --file or --dir")
		os.Exit(1)
	}

	s, err := scanner.New(sigDB)
	if err != nil {
		fmt.Printf("[!] Failed to load signature database: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Loaded %d signatures from %s\n\n", s.SignatureCount(), sigDB)

	if file != "" {
		scanSingleFile(s, file)
		return
	}

	// Directory scan
	var files []string
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		fmt.Printf("[!] Error walking directory: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Scanning directory: %s (%d files)\n\n", dir, len(files))
	detected := 0
	for _, f := range files {
		result := scanSingleFile(s, f)
		if result {
			detected++
		}
	}
	fmt.Printf("\n[*] Scan complete — %d/%d files flagged as malicious\n", detected, len(files))
}

// scanSingleFile scans one file and prints results. Returns true if detected.
func scanSingleFile(s *scanner.Scanner, path string) bool {
	fmt.Printf("[*] Scanning: %s\n", path)
	result, err := s.ScanFile(path)
	if err != nil {
		fmt.Printf("    [!] Error: %v\n\n", err)
		return false
	}

	if result.Detected {
		fmt.Printf("    [!] DETECTED\n")
		fmt.Printf("        Hash Type : %s\n", result.MatchType)
		fmt.Printf("        Hash      : %s\n", result.Hash)
		fmt.Printf("        Signature : %s\n", result.MatchName)
		fmt.Printf("        Verdict   : MALICIOUS\n\n")
		return true
	}

	fmt.Printf("    [+] CLEAN\n")
	fmt.Printf("        MD5    : %s\n", result.MD5)
	fmt.Printf("        SHA1   : %s\n", result.SHA1)
	fmt.Printf("        SHA256 : %s\n\n", result.SHA256)
	return false
}

func runAddHash(hash, name, hashType string) {
	if hash == "" || name == "" {
		fmt.Println("[!] Error: --hash and --name are required")
		os.Exit(1)
	}

	hashType = strings.ToUpper(hashType)
	if hashType != "MD5" && hashType != "SHA1" && hashType != "SHA256" {
		fmt.Printf("[!] Invalid hash type: %s. Use MD5, SHA1, or SHA256\n", hashType)
		os.Exit(1)
	}

	f, err := os.OpenFile(sigDB, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		fmt.Printf("[!] Failed to open signature database: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	entry := fmt.Sprintf("%s|%s|%s\n", hashType, strings.ToLower(hash), name)
	if _, err := f.WriteString(entry); err != nil {
		fmt.Printf("[!] Failed to write hash: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] Added %s hash for \"%s\"\n", hashType, name)
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  astra-av scan --file <path>")
	fmt.Println("  astra-av scan --dir <path>")
	fmt.Println("  astra-av add-hash --hash <hash> --name <name> [--type MD5|SHA1|SHA256]")
}
