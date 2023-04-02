package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
)

// Scanner struct
type Scanner struct {
	RootDir         string
	Extensions      []string
	Vulnerabilities []Vulnerability
	Threads         int
}

// NewScanner creates a new scanner instance
func NewScanner(rootDir string, extensions []string, threads int, vulnerabilities []Vulnerability) *Scanner {
	return &Scanner{
		RootDir:         rootDir,
		Vulnerabilities: vulnerabilities,
		Threads:         threads,
		Extensions:      extensions,
	}
}

// Scan scans the directory and returns any Issues
func (s *Scanner) Scan() []Issue {
	var Issues []Issue
	var extLength int = len(s.Extensions)
	fileChan := make(chan string)
	var filePaths []string

	filepath.Walk(s.RootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		if extLength > 0 {
			// Check if file extension is in the list
			//fmt.Println(extLength)
			ext := filepath.Ext(path)
			if !stringInSlice(ext, s.Extensions) {
				return nil
			}
		}
		filePaths = append(filePaths, path)
		//fileChan <- path
		return nil
	})
	//fmt.Println(filePaths)
	filePathsCount := len(filePaths)
	if filePathsCount <= s.Threads {
		s.Threads = filePathsCount
	}
	if s.Threads < 1 || s.Threads > 99 {
		s.Threads = 10
	}
	//fmt.Println(s.Threads)
	var wg sync.WaitGroup
	// Launch worker goroutines
	for i := 0; i < s.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileChan {
				content, err := ioutil.ReadFile(path)
				if err != nil {
					log.Printf("Error reading file %s: %v", path, err)
					continue
				}
				for _, vulnerability := range s.Vulnerabilities {
					reg := regexp.MustCompile(vulnerability.Regex)
					matches := reg.FindAllStringSubmatchIndex(string(content), -1)
					for _, match := range matches {
						Issue := Issue{
							File:        path,
							Line:        s.getLineNumber(content, match),
							LineContent: s.getLine(content, match),
							Vuln:        vulnerability,
						}
						Issues = append(Issues, Issue)
					}
				}
			}
		}()
	}

	// Add paths to file channel
	go func() {
		for _, path := range filePaths {
			fileChan <- path
		}
		close(fileChan)
	}()

	// Wait for worker goroutines to finish
	wg.Wait()

	return Issues
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

func (s *Scanner) GenerateMarkdown(Issues []Issue) string {
	MarkDown := "# **RegInspect Vulnerability Report**\n\n"
	VulnerabilitiesHead := "## **Vulnerabilities** -\n\n"
	MarkDown = MarkDown + VulnerabilitiesHead
	SortBySeverity(Issues)
	severityChanged := ""
	for _, Issue := range Issues {
		if Issue.Vuln.Severity != severityChanged {
			MarkDown = MarkDown + "\n\n### **Severity: " + Issue.Vuln.Severity + "**" + "\n</br>"
			severityChanged = Issue.Vuln.Severity
		}
		MarkDown = MarkDown + "\n\n#### **Vulnerability: " + Issue.Vuln.Name + "**" + "\n" + "#### **Description**: " + Issue.Vuln.Description + "\n" + "#### **File Name**: " + Issue.File + "\n" + "#### **Line No**: " + strconv.Itoa(Issue.Line) + "\n" + "#### **Content**: " + "\n<pre>\n" + Issue.LineContent + "</pre>" + "\n</br>"
	}
	MarkDown = MarkDown + "\n\n\n\n"
	return MarkDown
}
func SortBySeverity(Issues []Issue) {
	sort.Slice(Issues, func(i, j int) bool {
		return sortBySeverity(Issues[i], Issues[j])
	})
}
func sortBySeverity(Issue1, Issue2 Issue) bool {
	severityOrder := map[string]int{
		"Critical":    4,
		"High":        3,
		"Medium":      2,
		"Low":         1,
		"Informative": 0,
		"QA":          -1,
	}
	return severityOrder[Issue1.Vuln.Severity] > severityOrder[Issue2.Vuln.Severity]
}

func stringInSlice(str string, list []string) bool {
	for _, v := range list {
		if v == str {
			return true
		}
	}
	return false
}
