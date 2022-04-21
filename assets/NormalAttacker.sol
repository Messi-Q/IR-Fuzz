pragma solidity ^0.4.2;

contract NormalAttacker {
  uint counter = 0;
  function() payable {
    revert();
  }
}
