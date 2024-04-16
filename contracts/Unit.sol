// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

//import "@imtbl/contracts/contracts/token/erc721/preset/ImmutableERC721.sol";
import "@imtbl/contracts/contracts/allowlist/OperatorAllowlistEnforced.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/token/ERC1155/extensions/ERC1155Burnable.sol";
import "@openzeppelin/contracts/token/ERC1155/extensions/ERC1155Supply.sol";

contract Unit is Ownable, Pausable, ERC1155Supply, OperatorAllowlistEnforced {

    string public name= "ScarQuestVoucherCollection";
    string public symbol= "SCVC";

    uint256 idBaseNormal;
    uint256 idBaseSilver;
    uint256 idBaseGold;

    uint256 maxIdNormal;
    uint256 maxIdSilver;
    uint256 maxIdGold;

    uint256 maxAmountSilver;

    constructor() ERC1155("") {

        _setURI("https://velhalla-game.s3.amazonaws.com/Image/Item/UnitCardVoucherV2/{id}.json");

        _setOperatorAllowlistRegistry(0x6b969FD89dE634d8DE3271EbE97734FEFfcd58eE);

        idBaseNormal = 1;
        idBaseSilver = 100001;
        idBaseGold = 1000001;

        maxIdNormal = 200;
        maxIdSilver = 100016;
        maxIdGold = 16000100;

        maxAmountSilver = 500;

    }

    // Function to mint more fungible tokens (onlyOwner)
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


    function mintBatch(address to, uint256[] memory ids, uint256[] memory amounts, bytes memory data) public onlyOwner whenNotPaused {
        _mintBatch(to, ids, amounts, data);
    }

    function setName (string memory _newName) public onlyOwner {
        name= _newName;
    }

    function setSymbol (string memory _newSymbol) public onlyOwner {
        symbol= _newSymbol;
    }

    function setURI(string memory _newUri) public onlyOwner {
        _setURI(_newUri);
    }

    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ERC1155, OperatorAllowlistEnforced) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}