import { ethers } from "ethers";

export default async function anchorToPolygon(hash) {
  try {

    const rpc = process.env.POLYGON_RPC_ENDPOINT;
    const key = process.env.POLYGON_PRIVATE_KEY;
    const chainId = Number(process.env.POLYGON_CHAIN_ID || 137);

    if (!rpc || !key) {
      console.log("Polygon not configured");
      return null;
    }

    console.log("Connecting to Polygon RPC:", rpc);

    const provider = new ethers.JsonRpcProvider(rpc);

    const wallet = new ethers.Wallet(key, provider);

    console.log("Wallet address:", wallet.address);

    const balance = await provider.getBalance(wallet.address);

    console.log("Wallet balance:", ethers.formatEther(balance), "MATIC");

    if (balance === 0n) {
      console.log("WARNING: Wallet has zero MATIC — transaction may fail");
    }

    const tx = await wallet.sendTransaction({
      to: wallet.address,
      value: 0n,
      data: ethers.hexlify(ethers.toUtf8Bytes(hash)),
      gasLimit: 100000n
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
