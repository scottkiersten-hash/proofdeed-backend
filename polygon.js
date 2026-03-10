import { ethers } from "ethers";
import dotenv from "dotenv";

dotenv.config();

const provider = new ethers.JsonRpcProvider(process.env.POLYGON_RPC_URL);

const wallet = new ethers.Wallet(
  process.env.POLYGON_PRIVATE_KEY,
  provider
);

export async function anchorToPolygon(hash) {
  try {

    console.log("Anchoring hash to Polygon:", hash);

    const tx = await wallet.sendTransaction({
      to: wallet.address,
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
