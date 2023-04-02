package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

func main() {
	printBanner()

	// Parse command line arguments
	dir := flag.String("dir", ".", "Directory to scan")
	jsonFile := flag.String("vuln", "", "JSON file containing vulnerabilities")
	ext := flag.String("ext", "", "Scan Files ending with specific extensions (comma-Separated)")
	out := flag.String("out", "RegInspect_Report.MD", "Path to Output File")
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

	//Get extensions list from user to scan files ending with specific extensions
	var extensions []string
	if *ext != "" {
		extensions = strings.Split(*ext, ",")
		for i, s := range extensions {
			extensions[i] = strings.TrimSpace(s)
			if !strings.HasPrefix(extensions[i], ".") {
				extensions[i] = "." + extensions[i]
			}
		}
	}

	// Create scanner and start scanning
	scanner := NewScanner(*dir, extensions, vulnerabilities)
	Issues := scanner.Scan()
	md := scanner.GenerateMarkdown(Issues)
	if *out != "" {
		err := ioutil.WriteFile(*out, []byte(md), 0644)
		if err != nil {
			fmt.Printf("Failed to write to output file: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("Output saved to %s\n", *out)

}

func printBanner() {
	banner := `

	_______  _______  _______ _________ _        _______  _______  _______  _______ _________
	(  ____ )(  ____ \(  ____ \\__   __/( (    /|(  ____ \(  ____ )(  ____ \(  ____ \\__   __/
	| (    )|| (    \/| (    \/   ) (   |  \  ( || (    \/| (    )|| (    \/| (    \/   ) (   
	| (____)|| (__    | |         | |   |   \ | || (_____ | (____)|| (__    | |         | |   
	|     __)|  __)   | | ____    | |   | (\ \) |(_____  )|  _____)|  __)   | |         | |   
	| (\ (   | (      | | \_  )   | |   | | \   |      ) || (      | (      | |         | |   
	| ) \ \__| (____/\| (___) |___) (___| )  \  |/\____) || )      | (____/\| (____/\   | |   
	|/   \__/(_______/(_______)\_______/|/    )_)\_______)|/       (_______/(_______/   )_(   
																							  
	
			
	`
	fmt.Println(banner)
}
