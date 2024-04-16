// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

import "@imtbl/contracts/contracts/token/erc721/preset/ImmutableERC721.sol";

contract IMX721 is ImmutableERC721 {
    constructor() ImmutableERC721(
        0xB91e77f09a769C84740FF07335901790971b6c60, //owner
        "ScarQuestVoucherCollection", //name
        "SCVC", //symbol
        "https://velhalla-game.s3.amazonaws.com/Image/Item/UnitCardVoucherV2/{id}.json",  //baseURI
        "https://velhalla-game.s3.amazonaws.com/Image/Item/UnitCardVoucherV2/{id}.json", // Contract URI
        0x6b969FD89dE634d8DE3271EbE97734FEFfcd58eE,     // Operator list
        0xB91e77f09a769C84740FF07335901790971b6c60, // Receiver
        2000 //fee numerator
    )
    {}
}