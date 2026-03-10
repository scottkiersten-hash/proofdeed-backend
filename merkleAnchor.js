import { MerkleTree } from "merkletreejs";
import keccak256 from "keccak256";
import anchorToPolygon from "./polygon.js";

/*
Queue of document hashes waiting to anchor
*/
let queue = [];

/*
Add document to batch
*/
export function queueHash(hash) {
  queue.push(hash);
}

/*
Process batch every minute
*/
export async function processBatch() {

  if (queue.length === 0) return;

  const hashes = [...queue];
  queue = [];

  const leaves = hashes.map(x => keccak256(x));

  const tree = new MerkleTree(leaves, keccak256, {
    sortPairs: true
  });

  const root = tree.getRoot().toString("hex");

  const polygon_tx = await anchorToPolygon(root);

  return {
    root,
    polygon_tx,
    tree,
    hashes
  };

}
