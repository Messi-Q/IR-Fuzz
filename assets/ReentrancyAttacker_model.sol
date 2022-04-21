pragma solidity ^0.4.2;

contract ReentrancyAttacker {
    uint256 counter = 0;

    function() external payable {
        counter++;
        if (counter <= 5) {
            msg.sender.call(abi.encode(keccak256("")));
        }
        revert();
    }
}
