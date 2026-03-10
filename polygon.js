import { ethers } from "ethers";

export default async function anchorToPolygon(hash) {

  try {

    const rpc =
      process.env.POLYGON_RPC_URL ||
      process.env.POLYGON_RPC;

    const key = process.env.POLYGON_PRIVATE_KEY;

    if (!rpc || !key) {
      console.log("Polygon not configured");
      return null;
    }

    const provider = new ethers.JsonRpcProvider(rpc);

    const wallet = new ethers.Wallet(key, provider);

    console.log("Wallet:", wallet.address);
    console.log("RPC:", rpc);

    const tx = await wallet.sendTransaction({
      to: wallet.address,
      value: 0n,
      data: ethers.hexlify(ethers.toUtf8Bytes(hash))
    });

    console.log("TX sent:", tx.hash);

    await tx.wait();

    console.log("TX confirmed");

    return tx.hash;

  } catch (err) {

    console.error("Polygon anchor failed:", err);

    return null;

  }

}
