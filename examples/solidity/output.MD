# **RegInspect Vulnerability Report**



## **Summary**</br>

| **Severity** | **Count** |
| -------- | ----- |
| Low | 2 |
| Informative | 5 |
</br></br>

## **Vulnerabilities** -



### **Severity: Low**</br>

#### </br>

### **Vulnerability: Unsafe ERC20 Operation(s) [SOL9]**
### **Description**: https://github.com/byterocket/c4-common-issues/blob/main/2-Low-Risk.md#l001---unsafe-erc20-operations</br></br>

#### **Issue ID**: 7


#### **File Name**: examples\solidity\SampleContract.sol
#### **Line No**: 16
#### **Content**: 
<pre>
        token.transferFrom(msg.sender, address(this), 100);</pre></br>
#### </br>

### **Vulnerability: Unspecific Compiler Version Pragma [SOL10]**
### **Description**: https://github.com/byterocket/c4-common-issues/blob/main/2-Low-Risk.md#l003---unspecific-compiler-version-pragma</br></br>

#### **Issue ID**: 8


#### **File Name**: examples\solidity\SampleContract.sol
#### **Line No**: 1
#### **Content**: 
<pre>
pragma solidity ^0.8.0;</pre></br>


### **Severity: Informative**</br>

#### </br>

### **Vulnerability: Don't Initialize Variables with Default Value [SOL1]**
### **Description**: Avoid initializing variables with default values like zero and false, as this generates unnecessary bytecode.</br></br>

#### **Issue ID**: 2


#### **File Name**: examples\solidity\SampleContract.sol
#### **Line No**: 4
#### **Content**: 
<pre>
    uint256 a = 0;</pre></br>


#### **Issue ID**: 3


#### **File Name**: examples\solidity\SampleContract.sol
#### **Line No**: 12
#### **Content**: 
<pre>
        for (uint256 i = 0; i < array.length; i++) {</pre></br>
#### </br>

### **Vulnerability: Cache Array Length Outside of Loop [SOL2]**
### **Description**: Cache the length of arrays outside of loops to save gas.</br></br>

#### **Issue ID**: 4


#### **File Name**: examples\solidity\SampleContract.sol
#### **Line No**: 12
#### **Content**: 
<pre>
        for (uint256 i = 0; i < array.length; i++) {</pre></br>
#### </br>

### **Vulnerability: Long Revert Strings [SOL7]**
### **Description**: Avoid using long revert strings as they increase the size of the contract and can use a lot of gas.</br></br>

#### **Issue ID**: 5


#### **File Name**: examples\solidity\SampleContract.sol
#### **Line No**: 6
#### **Content**: 
<pre>
    string b = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";</pre></br>
#### </br>

### **Vulnerability: Use Shift Right/Left instead of Division/Multiplication if possible [SOL8]**
### **Description**: Use shift right/left instead of division/multiplication with powers of 2 to save gas.</br></br>

#### **Issue ID**: 6


#### **File Name**: examples\solidity\SampleContract.sol
#### **Line No**: 13
#### **Content**: 
<pre>
            i = i / 2;</pre></br>




