import { ethers } from 'ethers';

export const CONTRACT_ADDRESS = "0x1E8461598caf86db994a0395A9389716e99f6d87";
export const CONTRACT_ABI = [
  {
    "inputs": [],
    "stateMutability": "nonpayable",
    "type": "constructor"
  },
  {
    "inputs": [
      {
        "internalType": "address",
        "name": "to",
        "type": "address"
      },
      {
        "internalType": "string",
        "name": "tokenURI",
        "type": "string"
      }
    ],
    "name": "mint",
    "outputs": [
      {
        "internalType": "uint256",
        "name": "",
        "type": "uint256"
      }
    ],
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "inputs": [
      {
        "internalType": "uint256",
        "name": "tokenId",
        "type": "uint256"
      }
    ],
    "name": "ownerOf",
    "outputs": [
      {
        "internalType": "address",
        "name": "",
        "type": "address"
      }
    ],
    "stateMutability": "view",
    "type": "function"
  }
];

export const getProvider = () => {
  return new ethers.providers.JsonRpcProvider("https://api.avax-test.network/ext/bc/C/rpc");
};

export const getContract = (provider) => {
  return new ethers.Contract(CONTRACT_ADDRESS, CONTRACT_ABI, provider);
};

export const getNFTDetails = async (tokenId) => {
  try {
    const provider = getProvider();
    const contract = getContract(provider);
    const owner = await contract.ownerOf(tokenId);
    return {
      owner,
      contract: CONTRACT_ADDRESS
    };
  } catch (error) {
    console.error('Error fetching NFT details:', error);
    return null;
  }
};
