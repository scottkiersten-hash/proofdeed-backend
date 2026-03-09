const { ethers } = require("ethers");

const provider = new ethers.JsonRpcProvider(process.env.POLYGON_RPC_URL);

const wallet = new ethers.Wallet(
  process.env.POLYGON_PRIVATE_KEY,
  provider
);

async function anchorHashToPolygon(hash) {

  try {

    const tx = await wallet.sendTransaction({
      to: wallet.address,
      value: 0,
      data: ethers.hexlify(ethers.toUtf8Bytes(hash))
    });

    console.log("Polygon TX:", tx.hash);

    return tx.hash;

  } catch (error) {

    console.error("Polygon anchor error:", error);

    return null;

  }

}

module.exports = { anchorHashToPolygon };
