import { ethers } from "ethers";

export default async function anchorToPolygon(hash) {
  try {
    const rpc = process.env.POLYGON_RPC_ENDPOINT;
    const key = process.env.POLYGON_PRIVATE_KEY;

    if (!rpc || !key) {
      console.log("Polygon not configured");
      return null;
    }

    const provider = new ethers.JsonRpcProvider(rpc, {
      chainId: Number(process.env.POLYGON_CHAIN_ID || 137),
      name: "polygon"
    });

    const wallet = new ethers.Wallet(key, provider);

    console.log("RPC:", rpc);
    console.log("Wallet:", wallet.address);

    const balance = await provider.getBalance(wallet.address);
    console.log("Wallet balance:", ethers.formatEther(balance));

    const tx = await wallet.sendTransaction({
      to: wallet.address,
      value: 0n,
      data: ethers.hexlify(ethers.toUtf8Bytes(hash))
    });

    console.log("TX submitted:", tx.hash);

    const receipt = await tx.wait();
    console.log("TX confirmed:", receipt.hash);

    return tx.hash;

  } catch (err) {
    console.error("POLYGON ERROR START");
    console.error(err);
    console.error("POLYGON ERROR END");
    return null;
  }
}
