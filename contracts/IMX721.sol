// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

import "@imtbl/contracts/contracts/token/erc721/preset/ImmutableERC721.sol";

contract IMX721 is ImmutableERC721 {
    constructor() ImmutableERC721(
        0xB91e77f09a769C84740FF07335901790971b6c60, //owner
        "ScarQuest Voucher Collection", //name
        "SCVC", //symbol
        "https://velhalla-game.s3.amazonaws.com/MetaData/Item/IMX/UnitCardVoucher_No{id}.json",  //baseURI
        "https://velhalla-game.s3.amazonaws.com/MetaData/Item/IMX/collection.json", // Contract URI
        0x5F5EBa8133f68ea22D712b0926e2803E78D89221,     // Operator list
        0xBdc994a2CD7a35A075ea2e4942d9CE30Cd6659eF, // Receiver
        2000 //fee numerator
    )
    {
        grantMinterRole(0xB91e77f09a769C84740FF07335901790971b6c60);
        grantMinterRole(0xf8B67051DE36fB576a09B4D2d66cD9f914741EC9);
    }
}