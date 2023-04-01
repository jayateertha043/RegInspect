package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

func main() {
	// Parse command line arguments
	dir := flag.String("dir", ".", "Directory to scan")
	out := flag.String("out", "RegInspect_Report.MD", "Path to Output File")
	jsonFile := flag.String("vuln", "", "JSON file containing vulnerabilities")
	flag.Parse()

	// Read vulnerability definitions from JSON file
	var vulnerabilities []Vulnerability
	if *jsonFile != "" {
		vulnData, err := ioutil.ReadFile(*jsonFile)
		if err != nil {
			fmt.Printf("Failed to read vulnerability data: %v\n", err)
			os.Exit(1)
		}
		err = json.Unmarshal(vulnData, &vulnerabilities)
		if err != nil {
			fmt.Printf("Failed to parse vulnerability data: %v\n", err)
			os.Exit(1)
		}
	}

	// Create scanner and start scanning
	scanner := NewScanner(*dir, vulnerabilities)
	findings := scanner.Scan()
	md := scanner.GenerateMarkdown(findings)
	if *out != "" {
		err := ioutil.WriteFile(*out, []byte(md), 0644)
		if err != nil {
			fmt.Printf("Failed to write to output file: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("Output saved to %s\n", *out)

}
