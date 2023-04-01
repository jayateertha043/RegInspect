# **RegInspect Vulnerability Report**

## **Vulnerabilities** -



### **Severity: Low**
</br>

#### **Vulnerability: Unsafe ERC20 Operation(s)**
#### **Description**: https://github.com/byterocket/c4-common-issues/blob/main/2-Low-Risk.md#l001---unsafe-erc20-operations
#### **File Name**: examples\solidity\SampleContract.sol
#### **Line No**: 16
#### **Content**: 
<pre>
        token.transferFrom(msg.sender, address(this), 100);</pre>
</br>

#### **Vulnerability: Unspecific Compiler Version Pragma**
#### **Description**: https://github.com/byterocket/c4-common-issues/blob/main/2-Low-Risk.md#l003---unspecific-compiler-version-pragma
#### **File Name**: examples\solidity\SampleContract.sol
#### **Line No**: 1
#### **Content**: 
<pre>
pragma solidity ^0.8.0;</pre>
</br>

### **Severity: Informative**
</br>

#### **Vulnerability: Don't Initialize Variables with Default Value**
#### **Description**: Avoid initializing variables with default values like zero and false, as this generates unnecessary bytecode.
#### **File Name**: examples\solidity\SampleContract.sol
#### **Line No**: 4
#### **Content**: 
<pre>
    uint256 a = 0;</pre>
</br>

#### **Vulnerability: Don't Initialize Variables with Default Value**
#### **Description**: Avoid initializing variables with default values like zero and false, as this generates unnecessary bytecode.
#### **File Name**: examples\solidity\SampleContract.sol
#### **Line No**: 12
#### **Content**: 
<pre>
        for (uint256 i = 0; i < array.length; i++) {</pre>
</br>

#### **Vulnerability: Cache Array Length Outside of Loop**
#### **Description**: Cache the length of arrays outside of loops to save gas.
#### **File Name**: examples\solidity\SampleContract.sol
#### **Line No**: 12
#### **Content**: 
<pre>
        for (uint256 i = 0; i < array.length; i++) {</pre>
</br>

#### **Vulnerability: Long Revert Strings**
#### **Description**: Avoid using long revert strings as they increase the size of the contract and can use a lot of gas.
#### **File Name**: examples\solidity\SampleContract.sol
#### **Line No**: 6
#### **Content**: 
<pre>
    string b = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";</pre>
</br>

#### **Vulnerability: Use Shift Right/Left instead of Division/Multiplication if possible**
#### **Description**: Use shift right/left instead of division/multiplication with powers of 2 to save gas.
#### **File Name**: examples\solidity\SampleContract.sol
#### **Line No**: 13
#### **Content**: 
<pre>
            i = i / 2;</pre>
</br>



