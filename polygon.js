import { ethers } from "ethers";
import dotenv from "dotenv";

dotenv.config();

let wallet;

function getPolygonWallet() {
  if (wallet) return wallet;

  const rpcUrl = process.env.POLYGON_RPC_URL;
  const privateKey = process.env.POLYGON_PRIVATE_KEY;

  if (!rpcUrl) {
    throw new Error("Missing POLYGON_RPC_URL environment variable");
  }

  if (!privateKey) {
    throw new Error("Missing POLYGON_PRIVATE_KEY environment variable");
  }

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  wallet = new ethers.Wallet(privateKey, provider);

  return wallet;
}

export async function anchorToPolygon(hash) {
  try {
    const signer = getPolygonWallet();

    console.log("Anchoring hash to Polygon:", hash);

    const tx = await signer.sendTransaction({
      to: signer.address,
      value: 0,
      data: ethers.hexlify(ethers.toUtf8Bytes(hash))
    });

    console.log("Transaction sent:", tx.hash);

    await tx.wait();

    console.log("Transaction confirmed");

    return tx.hash;

  } catch (error) {
    console.error("Polygon anchoring failed:", error);
    throw error;
  }
}
