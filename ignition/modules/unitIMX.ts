import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

export default buildModule("unitIMXmodule", (m) => {
  const unit = m.contract("UnitIMX");

  return { unit };
});