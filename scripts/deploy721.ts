import { ethers } from "hardhat";

async function main() {
    // Get the ContractFactory for the ImmutableERC721 contract
    const IMX721 = await ethers.getContractFactory("IMX721");

    // Deploy the contract
    const imx721 = await IMX721.deploy();


    // Log the address where the contract is deployed
    console.log("IMX721 deployed to:", await imx721.getAddress());
}

// Run the deployment script
main()
  .then(() => process.exit(0))
  .catch(error => {
    console.error(error);
    process.exit(1);
});
