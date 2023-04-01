pragma solidity ^0.8.0;

contract MyContract {
    string password = "secret123";
    
    function getPassword() public view returns(string memory) {
        return password;
    }
}