package scanner

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ============================================================
// ASTRA AV Engine — Episode 1: Hash-Based Detection
// scanner/scanner.go — Core scanning logic
// ============================================================

// Verdict represents the outcome of a file scan.
type Verdict string

const (
	VerdictMalicious Verdict = "MALICIOUS"
	VerdictClean     Verdict = "CLEAN"
	VerdictError     Verdict = "ERROR"
)

// ScanResult holds the full result of scanning a single file.
type ScanResult struct {
	FilePath   string
	MD5        string
	SHA1       string
	SHA256     string
	Detected   bool
	MatchType  string // e.g. "SHA256", "MD5", "SHA1"
	MatchHash  string // the specific hash that matched
	ThreatName string
	Verdict    Verdict
	ScanTime   time.Duration
	Error      error
}

// Signature represents a single entry in the hash database.
type Signature struct {
	HashType   string // "MD5", "SHA1", "SHA256"
	Hash       string
	ThreatName string
}

// SignatureDB holds all loaded signatures, indexed by hash value for fast lookup.
type SignatureDB struct {
	entries map[string]Signature // key: lowercase hash value
}

// LoadSignatures reads the pipe-delimited hashes.txt file into a SignatureDB.
// Lines starting with '#' or that are blank are skipped.
// Expected format: HASH_TYPE|HASH|THREAT_NAME
func LoadSignatures(path string) (*SignatureDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not open signature database: %w", err)
	}
	defer f.Close()

	db := &SignatureDB{entries: make(map[string]Signature)}
	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 3 {
			fmt.Fprintf(os.Stderr, "[WARN] Skipping malformed line %d in signature database\n", lineNum)
			continue
		}

		sig := Signature{
			HashType:   strings.ToUpper(strings.TrimSpace(parts[0])),
			Hash:       strings.ToLower(strings.TrimSpace(parts[1])),
			ThreatName: strings.TrimSpace(parts[2]),
		}
		db.entries[sig.Hash] = sig
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading signature database: %w", err)
	}

	return db, nil
}

// Lookup checks whether a given hash (any type) is in the database.
func (db *SignatureDB) Lookup(hashValue string) (Signature, bool) {
	sig, found := db.entries[strings.ToLower(hashValue)]
	return sig, found
}

// Count returns the number of signatures loaded.
func (db *SignatureDB) Count() int {
	return len(db.entries)
}

// AddSignature appends a new signature to the hashes.txt file.
func AddSignature(dbPath, hashType, hashValue, threatName string) error {
	f, err := os.OpenFile(dbPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("could not open signature database for writing: %w", err)
	}
	defer f.Close()

	line := fmt.Sprintf("%s|%s|%s\n",
		strings.ToUpper(hashType),
		strings.ToLower(hashValue),
		threatName,
	)
	_, err = f.WriteString(line)
	return err
}

// hashFile computes MD5, SHA-1, and SHA-256 of a file in a single pass.
func hashFile(path string) (md5sum, sha1sum, sha256sum string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", "", fmt.Errorf("could not open file: %w", err)
	}
	defer f.Close()

	hMD5 := md5.New()
	hSHA1 := sha1.New()
	hSHA256 := sha256.New()

	// Write to all three hashers in one pass using io.MultiWriter
	multi := io.MultiWriter([]io.Writer{hMD5, hSHA1, hSHA256}...)
	if _, err := io.Copy(multi, f); err != nil {
		return "", "", "", fmt.Errorf("could not hash file: %w", err)
	}

	return hashHex(hMD5), hashHex(hSHA1), hashHex(hSHA256), nil
}

func hashHex(h hash.Hash) string {
	return hex.EncodeToString(h.Sum(nil))
}

// ScanFile scans a single file against the signature database.
func ScanFile(path string, db *SignatureDB) ScanResult {
	start := time.Now()
	result := ScanResult{
		FilePath: path,
		Verdict:  VerdictClean,
	}

	md5sum, sha1sum, sha256sum, err := hashFile(path)
	if err != nil {
		result.Error = err
		result.Verdict = VerdictError
		result.ScanTime = time.Since(start)
		return result
	}

	result.MD5 = md5sum
	result.SHA1 = sha1sum
	result.SHA256 = sha256sum

	// Check all three hashes — stop at first match
	for _, candidate := range []struct {
		hashType string
		value    string
	}{
		{"SHA256", sha256sum},
		{"SHA1", sha1sum},
		{"MD5", md5sum},
	} {
		if sig, found := db.Lookup(candidate.value); found {
			result.Detected = true
			result.MatchType = candidate.hashType
			result.MatchHash = candidate.value
			result.ThreatName = sig.ThreatName
			result.Verdict = VerdictMalicious
			break
		}
	}

	result.ScanTime = time.Since(start)
	return result
}

// ScanDirectory recursively scans all files in a directory.
func ScanDirectory(root string, db *SignatureDB) []ScanResult {
	var results []ScanResult

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			results = append(results, ScanResult{
				FilePath: path,
				Verdict:  VerdictError,
				Error:    err,
			})
			return nil // continue walking
		}
		if info.IsDir() {
			return nil
		}
		results = append(results, ScanFile(path, db))
		return nil
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Directory walk failed: %v\n", err)
	}

	return results
}
