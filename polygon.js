import { ethers } from "ethers";

export default async function anchorToPolygon(hash) {
  try {
    // Get the Polygon RPC endpoint, private key, and chain ID from environment variables
    const rpc = process.env.POLYGON_RPC_ENDPOINT;
    const key = process.env.POLYGON_PRIVATE_KEY;
    const chainId = Number(process.env.POLYGON_CHAIN_ID || 137);

    // Check if the Polygon RPC and key are properly configured
    if (!rpc || !key) {
      console.log("Error: Polygon RPC endpoint or private key not configured correctly");
      return null;
    }

    console.log("Connecting to Polygon RPC:", rpc);

    // Create a provider using the configured Polygon RPC
    const provider = new ethers.JsonRpcProvider(rpc);

    // Create a wallet from the private key
    const wallet = new ethers.Wallet(key, provider);

    console.log("Wallet address:", wallet.address);

    // Check the wallet balance
    const balance = await provider.getBalance(wallet.address);

    console.log("Wallet balance:", ethers.formatEther(balance), "MATIC");

    if (balance === 0n) {
      console.log("WARNING: Wallet has zero MATIC — transaction may fail");
    }

    // Send a test transaction to the Polygon network with the hash as data
    const tx = await wallet.sendTransaction({
      to: wallet.address,
      value: 0n, // No MATIC sent, just test data
      data: ethers.hexlify(ethers.toUtf8Bytes(hash)), // Hash as transaction data
      gasLimit: 100000n // Set a gas limit for the transaction
    });

    console.log("TX submitted:", tx.hash);

    // Wait for the transaction to be mined and get the receipt
    const receipt = await tx.wait();

    console.log("TX confirmed:", receipt.hash);

    // Return the transaction hash upon successful completion
    return tx.hash;

  } catch (err) {
    console.error("POLYGON ERROR START");
    console.error(err);
    console.error("POLYGON ERROR END");
    return null;
  }
}
