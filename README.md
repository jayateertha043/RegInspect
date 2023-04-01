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
Usage of RegInspect:
  -dir string
        Directory to scan (default ".")
  -out string
        Path to Output File (default "RegInspect_Report.MD")
  -vuln string
        JSON file containing vulnerabilities
```

```
RegInspect.exe -dir ./examples/solidity -out ./examples/solidity/output.MD -vuln ./rules/solidity/rules.json
```


## Author

👤 **Jayateertha G**

* Twitter: [@jayateerthaG](https://twitter.com/jayateerthaG)
* Github: [@jayateertha043](https://github.com/jayateertha043)
