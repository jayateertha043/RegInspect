package main

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
)

// Scanner struct
type Scanner struct {
	RootDir         string
	Vulnerabilities []Vulnerability
}

// NewScanner creates a new scanner instance
func NewScanner(rootDir string, vulnerabilities []Vulnerability) *Scanner {
	return &Scanner{
		RootDir:         rootDir,
		Vulnerabilities: vulnerabilities,
	}
}

// Scan scans the directory and returns any findings
func (s *Scanner) Scan() []Finding {
	var findings []Finding

	filepath.Walk(s.RootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		content, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}
		for _, vulnerability := range s.Vulnerabilities {
			reg := regexp.MustCompile(vulnerability.Regex)
			matches := reg.FindAllStringSubmatchIndex(string(content), -1)
			for _, match := range matches {
				finding := Finding{
					File:        path,
					Line:        s.getLineNumber(content, match),
					LineContent: s.getLine(content, match),
					Vuln:        vulnerability,
				}
				findings = append(findings, finding)
			}
		}
		return nil
	})

	return findings
}

func (s *Scanner) getLine(content []byte, match []int) string {
	lineStart := bytes.LastIndex(content[:match[0]], []byte("\n")) + 1
	lineEnd := bytes.Index(content[match[1]:], []byte("\n"))
	if lineEnd == -1 {
		lineEnd = len(content)
	} else {
		lineEnd += match[1]
	}
	return string(content[lineStart:lineEnd])
}

func (s *Scanner) getLineNumber(content []byte, match []int) int {
	lineStart := regexp.MustCompile(`(?m)^`).FindIndex(content[0:match[0]])
	return len(regexp.MustCompile(`\n`).FindAll(content[0:match[0]], -1)) + len(lineStart) - 1
}

func (s *Scanner) GenerateMarkdown(findings []Finding) string {
	MarkDown := "# **RegInspect Vulnerability Report**\n\n"
	VulnerabilitiesHead := "## **Vulnerabilities** -\n\n"
	MarkDown = MarkDown + VulnerabilitiesHead
	SortBySeverity(findings)
	severityChanged := ""
	for _, finding := range findings {
		if finding.Vuln.Severity != severityChanged {
			MarkDown = MarkDown + "\n\n### **Severity: " + finding.Vuln.Severity + "**" + "\n</br>"
			severityChanged = finding.Vuln.Severity
		}
		MarkDown = MarkDown + "\n\n#### **Vulnerability: " + finding.Vuln.Name + "**" + "\n" + "#### **Description**: " + finding.Vuln.Description + "\n" + "#### **File Name**: " + finding.File + "\n" + "#### **Line No**: " + strconv.Itoa(finding.Line) + "\n" + "#### **Content**: " + "\n<pre>\n" + finding.LineContent + "</pre>" + "\n</br>"
	}
	MarkDown = MarkDown + "\n\n\n\n"
	return MarkDown
}
func SortBySeverity(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		return sortBySeverity(findings[i], findings[j])
	})
}
func sortBySeverity(finding1, finding2 Finding) bool {
	severityOrder := map[string]int{
		"Critical":    4,
		"High":        3,
		"Medium":      2,
		"Low":         1,
		"Informative": 0,
		"QA":          -1,
	}
	return severityOrder[finding1.Vuln.Severity] > severityOrder[finding2.Vuln.Severity]
}
