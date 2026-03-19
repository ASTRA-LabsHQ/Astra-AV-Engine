package scanner

// ============================================================
// ASTRA AV Engine — Episode 2: YARA Rule Scanning
// scanner/yara.go — YARA scanning via CLI subprocess
// No CGo required — shells out to the yara binary.
// ============================================================

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// YaraMatch holds the details of a single YARA rule match.
type YaraMatch struct {
	RuleName  string
	Namespace string
	Tags      []string
	Strings   []YaraMatchString
}

// YaraMatchString holds a single matched string from a YARA rule.
type YaraMatchString struct {
	Name   string
	Offset uint64
	Data   []byte
}

// YaraScanner holds the path to the rules file/directory.
type YaraScanner struct {
	rulesPath  string
	rulesCount int
}

// reMatchString parses a line like: 0x1234:$a: some data
var reMatchString = regexp.MustCompile(`^0x([0-9a-fA-F]+):(\$\S+):\s*(.*)$`)

// LoadYaraRules validates the rules path and does a test compile via the yara binary.
// Returns a YaraScanner and the number of rule files found.
func LoadYaraRules(path string) (*YaraScanner, int, error) {
	files, err := collectRuleFiles(path)
	if err != nil {
		return nil, 0, err
	}
	if len(files) == 0 {
		return nil, 0, fmt.Errorf("no .yar or .yara files found at: %s", path)
	}

	// Test-compile each file to catch syntax errors early
	for _, f := range files {
		cmd := exec.Command("yara", f, os.DevNull)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			errMsg := stderr.String()
			// A "could not open file" on DevNull is fine — rules compiled OK
			if !strings.Contains(errMsg, "could not open file") &&
				!strings.Contains(errMsg, "No such file") {
				return nil, 0, fmt.Errorf("YARA rule error in %s: %s", filepath.Base(f), errMsg)
			}
		}
	}

	return &YaraScanner{rulesPath: path, rulesCount: len(files)}, len(files), nil
}

// ScanFileYara runs the yara CLI against a single file and parses the output.
func (ys *YaraScanner) ScanFileYara(path string) ([]YaraMatch, error) {
	files, err := collectRuleFiles(ys.rulesPath)
	if err != nil {
		return nil, err
	}

	var allMatches []YaraMatch

	for _, ruleFile := range files {
		// -s prints matched strings, -w suppresses warnings
		cmd := exec.Command("yara", "-s", "-w", ruleFile, path)
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			// Exit code 1 with no stdout = no matches (not an error)
			// Exit code 1 with stderr = real error
			if stderr.Len() > 0 {
				return nil, fmt.Errorf("yara error: %s", stderr.String())
			}
		}

		if stdout.Len() == 0 {
			continue
		}

		// Derive namespace from filename (without extension)
		ns := strings.TrimSuffix(filepath.Base(ruleFile), filepath.Ext(ruleFile))
		matches := parseYaraOutput(stdout.String(), ns)
		allMatches = append(allMatches, matches...)
	}

	return allMatches, nil
}

// parseYaraOutput parses the output of `yara -s`.
// Output format:
//
//	RuleName /path/to/file
//	0xOFFSET:$string_name: matched data
func parseYaraOutput(output, namespace string) []YaraMatch {
	var matches []YaraMatch
	var current *YaraMatch

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Lines starting with 0x are matched string lines
		if strings.HasPrefix(line, "0x") {
			if current == nil {
				continue
			}
			m := reMatchString.FindStringSubmatch(strings.TrimSpace(line))
			if m == nil {
				continue
			}
			offset, _ := strconv.ParseUint(m[1], 16, 64)
			current.Strings = append(current.Strings, YaraMatchString{
				Name:   m[2],
				Offset: offset,
				Data:   parseMatchData(m[3]),
			})
			continue
		}

		// Otherwise it's a rule match line: "RuleName [tags] /path"
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		ruleName := parts[0]
		tags := []string{}

		// Check for tags in brackets: RuleName [tag1,tag2] /path
		if len(parts) >= 3 && strings.HasPrefix(parts[1], "[") {
			tagStr := strings.Trim(parts[1], "[]")
			if tagStr != "" {
				tags = strings.Split(tagStr, ",")
			}
		}

		matches = append(matches, YaraMatch{
			RuleName:  ruleName,
			Namespace: namespace,
			Tags:      tags,
		})
		current = &matches[len(matches)-1]
	}

	return matches
}

// parseMatchData attempts to decode hex-encoded match data from yara -s output.
func parseMatchData(s string) []byte {
	cleaned := strings.TrimSpace(s)
	if strings.HasPrefix(cleaned, "{") && strings.HasSuffix(cleaned, "}") {
		hexStr := strings.ReplaceAll(cleaned[1:len(cleaned)-1], " ", "")
		if b, err := hex.DecodeString(hexStr); err == nil {
			return b
		}
	}
	return []byte(cleaned)
}

// collectRuleFiles returns all .yar/.yara files at the given path.
// If path is a file, returns just that file. If a directory, walks it recursively.
func collectRuleFiles(path string) ([]string, error) {
	if _, err := exec.LookPath("yara"); err != nil {
		return nil, fmt.Errorf("yara binary not found — make sure YARA is installed and in PATH")
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("could not access rules path %s: %w", path, err)
	}

	var files []string

	if !info.IsDir() {
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yar" && ext != ".yara" {
			return nil, fmt.Errorf("rules file must have .yar or .yara extension: %s", path)
		}
		return []string{path}, nil
	}

	err = filepath.Walk(path, func(p string, fi os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		if fi.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext == ".yar" || ext == ".yara" {
			files = append(files, p)
		}
		return nil
	})

	return files, err
}
