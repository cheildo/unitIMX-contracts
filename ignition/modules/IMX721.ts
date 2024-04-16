import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("IMX721Module", (m) => {
  const IMX721contract = m.contract("IMX721");
  

  return { IMX721contract };
});