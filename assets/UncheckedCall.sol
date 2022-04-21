pragma solidity ^0.4.2;

contract UncheckedCall {
    function() payable{
        assert(false);
  }
}
