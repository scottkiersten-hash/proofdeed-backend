import { ethers } from "ethers";

const rpc =
  process.env.POLYGON_RPC_URL ||
  "https://polygon.llamarpc.com";

const key = process.env.POLYGON_PRIVATE_KEY;

let buffer = [];
let processing = false;

export default async function anchorToPolygon(hash) {

  buffer.push(hash);

  if (processing) {
    return null;
  }

  processing = true;

  setTimeout(async () => {

    try {

      if (!rpc || !key) {
        console.log("Polygon not configured");
        return;
      }

      const provider = new ethers.JsonRpcProvider(rpc);
      const wallet = new ethers.Wallet(key, provider);

      console.log("Anchoring batch:", buffer.length);

      const combined = buffer.join("|");

      const tx = await wallet.sendTransaction({
        to: wallet.address,
        value: 0n,
        data: ethers.hexlify(ethers.toUtf8Bytes(combined)),
        gasLimit: 60000n
      });

      console.log("Polygon TX:", tx.hash);

      await tx.wait();

      buffer = [];
      processing = false;

    } catch (err) {

      console.error("Batch anchor error:", err);
      processing = false;

    }

  }, 30000);

  return null;

}
