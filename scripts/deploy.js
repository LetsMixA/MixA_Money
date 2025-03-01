async function main() {
  try {
    // Check if private key is available
    if (!process.env.PRIVATE_KEY) {
      throw new Error("Missing PRIVATE_KEY environment variable");
    }

    const [deployer] = await ethers.getSigners();
    console.log("Deploying contracts with the account:", deployer.address);

    const balance = await deployer.getBalance();
    console.log("Account balance:", ethers.utils.formatEther(balance), "AVAX");

    const MixANFT = await ethers.getContractFactory("MixANFT");
    console.log("Deploying MixANFT...");
    const mixaNFT = await MixANFT.deploy();
    
    console.log("Waiting for deployment transaction to be mined...");
    await mixaNFT.deployed();

    console.log("MixANFT deployed to:", mixaNFT.address);
    
    // Update the contract address in web3auth.js
    const fs = require('fs');
    const web3AuthPath = './static/js/web3auth.js';
    let web3AuthContent = fs.readFileSync(web3AuthPath, 'utf8');
    web3AuthContent = web3AuthContent.replace(
      /const MixANFTAddress = '0x0000000000000000000000000000000000000000'/,
      `const MixANFTAddress = '${mixaNFT.address}'`
    );
    fs.writeFileSync(web3AuthPath, web3AuthContent);
    console.log("Updated contract address in web3auth.js");

    return mixaNFT.address;
  } catch (error) {
    console.error("Deployment failed:", error.message);
    throw error;
  }
}

main()
  .then((address) => {
    console.log("Deployment completed successfully");
    process.exit(0);
  })
  .catch((error) => {
    console.error("Deployment failed:", error);
    process.exit(1);
  });
