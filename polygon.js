import { ethers } from "ethers";

export default async function anchorToPolygon(hash) {
  try {
    if (!process.env.POLYGON_RPC_URL || !process.env.POLYGON_PRIVATE_KEY) {
      console.log("Polygon not configured");
      return null;
    }

    const provider = new ethers.JsonRpcProvider(process.env.POLYGON_RPC_URL);

    const wallet = new ethers.Wallet(
      process.env.POLYGON_PRIVATE_KEY,
      provider
    );

    console.log("Server wallet address:", wallet.address);

    const tx = await wallet.sendTransaction({
      to: wallet.address,
      value: 0n,
      data: ethers.hexlify(ethers.toUtf8Bytes(hash))
    });

    console.log("TX submitted:", tx.hash);

    await tx.wait();

    console.log("TX confirmed:", tx.hash);

    return tx.hash;

  } catch (err) {
    console.error("Polygon anchor failed:", err);
    return null;
  }
}
