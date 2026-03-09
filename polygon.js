import { ethers } from "ethers";

const provider = new ethers.JsonRpcProvider(process.env.POLYGON_RPC_URL);

const wallet = new ethers.Wallet(
  process.env.POLYGON_PRIVATE_KEY,
  provider
);

export default async function anchorToPolygon(hash) {

  try {

    const tx = await wallet.sendTransaction({
      to: wallet.address,
      value: 0,
      data: ethers.hexlify(ethers.toUtf8Bytes(hash))
    });

    await tx.wait();

    console.log("Polygon anchor tx:", tx.hash);

    return tx.hash;

  } catch (err) {

    console.error("Polygon anchor error:", err);

  }

}
