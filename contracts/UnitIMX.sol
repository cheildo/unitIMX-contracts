// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@imtbl/contracts/contracts/token/erc1155/preset/ImmutableERC1155.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

contract UnitIMX is Ownable, Pausable, ImmutableERC1155 {

    string public name= "ScarQuestVoucherCollection";
    string public symbol= "SCVC";

    uint256 idBaseNormal;
    uint256 idBaseSilver;
    uint256 idBaseGold;

    uint256 maxIdNormal;
    uint256 maxIdSilver;
    uint256 maxIdGold;

    uint256 maxAmountSilver;

    constructor() ImmutableERC1155(
        0xB91e77f09a769C84740FF07335901790971b6c60, //owner
        "ScarQuestVoucherCollection", //name
        "https://velhalla-game.s3.amazonaws.com/Image/Item/UnitCardVoucherV2/{id}.json",  //baseURI
        "https://velhalla-game.s3.amazonaws.com/Image/Item/UnitCardVoucherV2/{id}.json", // Contract URI
        0x6b969FD89dE634d8DE3271EbE97734FEFfcd58eE,     // Operator list
        0xB91e77f09a769C84740FF07335901790971b6c60, // Receiver
        2000 //fee numerator
    ) {

        idBaseNormal = 1;
        idBaseSilver = 100001;
        idBaseGold = 1000001;

        maxIdNormal = 200;
        maxIdSilver = 100016;
        maxIdGold = 16000100;

        maxAmountSilver = 500;

    }

    //Function to mint more fungible tokens (onlyOwner)
    function mintNormalCard(
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) public onlyOwner {
        require(id>=idBaseNormal && id<=maxIdNormal, "mintNormalCard: id should be between 1 and 16");
        _mint(to, id, amount, data);
    }

    // Function to mint more fungible tokens (onlyOwner)
    function mintSilverCard(
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) public onlyOwner whenNotPaused {
        require(id>=idBaseSilver && id<=maxIdSilver, "mintSilverCard: id should be between 100001 and 100016");
        require(totalSupply(id) <= maxAmountSilver, "mintSilverCard: Max amount reached");
        _mint(to, id, amount, data);
    }

    // Function to mint more non-fungible tokens (onlyOwner)
    function mintGoldCard (
        address to,
        uint256 id,
        bytes memory data
    ) public onlyOwner whenNotPaused {
        require(id>=idBaseGold && id<=maxIdGold, "mintGoldCard: id should be between 1000001 and 16000100");
        require(totalSupply(id) < 1, "mintGoldCard: tokenID already minted");
        _mint(to, id, 1, data);
    }


    function setName (string memory _newName) public onlyOwner {
        name= _newName;
    }

    function setSymbol (string memory _newSymbol) public onlyOwner {
        symbol= _newSymbol;
    }

    // function setURI(string memory _newUri) public onlyOwner {
    //     baseURI(_newUri);
    // }

}