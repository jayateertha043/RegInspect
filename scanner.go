package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
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
	var mu sync.Mutex
	var Issues []Issue
	var extLength int = len(s.Extensions)
	fileChan := make(chan string)
	var filePaths []string
	var issueID int = 1
	filepath.Walk(s.RootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		if extLength > 0 {
			ext := filepath.Ext(path)
			if !stringInSlice(ext, s.Extensions) {
				return nil
			}
		}
		filePaths = append(filePaths, path)
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
						mu.Lock()
						issueID = issueID + 1
						Issue := Issue{
							File:        path,
							Line:        s.getLineNumber(content, match),
							LineContent: s.getLine(content, match),
							Vuln:        vulnerability,
							IssueID:     issueID,
						}
						Issues = append(Issues, Issue)
						mu.Unlock()
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

	// group issues by severity and issue ID
	severityIDGroups := make(map[string]map[string][]Issue)
	for _, issue := range Issues {
		if _, ok := severityIDGroups[issue.Vuln.Severity]; !ok {
			severityIDGroups[issue.Vuln.Severity] = make(map[string][]Issue)
		}
		severityIDGroups[issue.Vuln.Severity][issue.Vuln.ID] = append(severityIDGroups[issue.Vuln.Severity][issue.Vuln.ID], issue)
	}
	// generate severity count table
	severityCountTable := "| **Severity** | **Count** |\n| -------- | ----- |\n"
	severityCount := make(map[string]int)
	for _, issue := range Issues {
		severityCount[issue.Vuln.Severity]++
	}

	for _, severity := range []string{"Critical", "High", "Medium", "Low", "Informative", "QA"} {
		if count, ok := severityCount[severity]; ok {
			severityCountTable += fmt.Sprintf("| %s | %d |\n", severity, count)
		}
	}

	MarkDown += "\n\n## **Summary**</br>\n\n"
	MarkDown += severityCountTable + "</br></br>\n\n"
	VulnerabilitiesHead := "## **Vulnerabilities** -\n\n"
	MarkDown = MarkDown + VulnerabilitiesHead

	// iterate through severity groups in order of decreasing severity
	severityOrder := []string{"Critical", "High", "Medium", "Low", "Informative", "QA"}
	for _, severity := range severityOrder {
		if _, ok := severityIDGroups[severity]; ok {
			MarkDown += "\n\n### **Severity: " + severity + "**</br>\n\n"
			for _, idGroup := range severityIDGroups[severity] {

				vulnName := ""
				vulnDesc := ""
				for _, issue := range idGroup {
					issueID := issue.IssueID
					if vulnName == "" && vulnDesc == "" {
						vulnName = issue.Vuln.Name
						vulnDesc = issue.Vuln.Description
						MarkDown = MarkDown + "#### </br>"
						MarkDown += "\n\n### **Vulnerability: " + vulnName + " [" + issue.Vuln.ID + "]" + "**\n" +
							"### **Description**: " + vulnDesc + "</br></br>"
					}
					MarkDown += "\n\n#### **Issue ID**: " + strconv.Itoa(issueID) + "\n" + "\n\n#### **File Name**: " + issue.File + "\n" +
						"#### **Line No**: " + strconv.Itoa(issue.Line) + "\n" +
						"#### **Content**: " + "\n<pre>\n" + issue.LineContent + "</pre></br>\n"
				}
			}
		}
	}

	MarkDown += "\n\n\n\n"
	return MarkDown
}

func stringInSlice(str string, list []string) bool {
	for _, v := range list {
		if v == str {
			return true
		}
	}
	return false
}
