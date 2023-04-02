<h1 align="center">RegInspect</h1>

RegInspect is a static analysis tool that uses regular expressions to detect vulnerabilities in source code. It is designed to be language-agnostic, meaning that it can be used with any programming language.

## Features
1. Customizable rules and regular expressions.
2. Detects vulnerabilities using regular expressions.
3. Supports multiple programming languages.
4. Generates Vulnerability report in MarkDown.


## REQUIREMENTS AND INSTALLATION

Build RegInspect:
```
git clone https://github.com/jayateertha043/RegInspect.git
cd RegInspect
go build .
```

or

Install using go install:

```
go install github.com/jayateertha043/RegInspect@latest
```

Run RegInspect:

```
RegInspect -h
```


## Usage

```
        _______  _______  _______ _________ _        _______  _______  _______  _______ _________
        (  ____ )(  ____ \(  ____ \\__   __/( (    /|(  ____ \(  ____ )(  ____ \(  ____ \\__   __/
        | (    )|| (    \/| (    \/   ) (   |  \  ( || (    \/| (    )|| (    \/| (    \/   ) (
        | (____)|| (__    | |         | |   |   \ | || (_____ | (____)|| (__    | |         | |
        |     __)|  __)   | | ____    | |   | (\ \) |(_____  )|  _____)|  __)   | |         | |
        | (\ (   | (      | | \_  )   | |   | | \   |      ) || (      | (      | |         | |
        | ) \ \__| (____/\| (___) |___) (___| )  \  |/\____) || )      | (____/\| (____/\   | |
        |/   \__/(_______/(_______)\_______/|/    )_)\_______)|/       (_______/(_______/   )_(



Usage of RegInspect.exe:
  -dir string
        Directory to scan (default ".")
  -ext string
        Scan Files ending with specific extensions (comma-Separated)
  -out string
        Path to Output File (default "RegInspect_Report.MD")
  -threads int
        No. Of Threads (default 10)
  -vuln string
        JSON file containing vulnerabilities
```

```
RegInspect -dir ./examples/solidity -out ./examples/solidity/output.MD -vuln ./rules/solidity/rules.json
```


## Credits
1. [@byterocket](https://github.com/byterocket) (For common solidity issues & inspiration drawn from c4udit tool.)


## Author

👤 **Jayateertha G**

* Twitter: [@jayateerthaG](https://twitter.com/jayateerthaG)
* Github: [@jayateertha043](https://github.com/jayateertha043)
