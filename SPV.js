const bsv = require('bsv');

//https://www.bitpaste.app/tx/01c5a66cd482cca4a7df4652376be33bdb10bf89a40bbb043d79f145397b7f33
 /**
 * Calculate the merkle root from an array of all the TXIDs in a full block
 *
 * @example
 * ```javascript
 * const merkleRoot = calculateMerkleRoot(
 *   [
 *     "c1d32f28baa27a376ba977f6a8de6ce0a87041157cef0274b20bfda2b0d8df96",
 *     "7e0ba1980522125f1f40d19a249ab3ae036001b991776813d25aebe08e8b8a50",
 *     "5c4d44b9b8d2ec6e0835ac90f206cecb26bf51033f31d4c659975b7534853409"
 *   ],
 * );
 * ```
 * @name calculateMerkleRoot
 * @function
 * @param {Array} hashes
 * @return {string}
 */
function calculateMerkleRoot(hashes){
    if(hashes.length === 1) {
        return hashes[0];
    }
    let branches = hashes.map(h => bsv.deps.Buffer.from(h, 'hex').reverse());
    while(branches.length>1){
        let layer = [];
        for(let i=0; i<branches.length; i+=2){
            if(branches[i]){
                const pair = branches[i+1] ? [branches[i], branches[i+1]] : [branches[i], branches[i]];
                layer.push(bsv.crypto.Hash.sha256sha256(bsv.deps.Buffer.concat(pair)));
            }
        }
        branches = layer;
    }
    return branches[0].reverse().toString('hex');
}

 /**
 * Calculate the merkle root of an SPV proof from the TXID, its 0th 
 * position in a block, and an array of hashes that it pairs with.
 * 
 * @example
 * ```javascript
 * const merkleRoot = calculateSPVMerkleRoot(
 *   '7e0ba1980522125f1f40d19a249ab3ae036001b991776813d25aebe08e8b8a50',
 *   1,
 *   [
 *     'c1d32f28baa27a376ba977f6a8de6ce0a87041157cef0274b20bfda2b0d8df96',
 *     '1e3a5a8946e0caf07006f6c4f76773d7e474d4f240a276844f866bd09820adb3'
 *   ]
 * );
 * ```
 * @name calculateSPVMerkleRoot
 * @function
 * @param {string} txid
 * @param {number} pos
 * @param {Array} merkle
 * @return {string}
 */
function calculateSPVMerkleRoot(txid, pos, merkle) {
    if(!merkle.length && pos===0) {
        return txid;
    }
    let tx = bsv.deps.Buffer.from(txid, 'hex').reverse();
    let hashes = merkle.map(h => bsv.deps.Buffer.from(h, 'hex').reverse());
    let index = pos;
    while(hashes.length){
        const pair = (index%2===0) ? [tx, hashes.shift()] : [hashes.shift(), tx];
        tx = bsv.crypto.Hash.sha256sha256(bsv.deps.Buffer.concat(pair));
        index = Math.floor(index/2);
    }
    return tx.reverse().toString('hex');
}

 /**
 * Create a merkle proof from a txid and an array of all the TXIDs in a block
 * 
 * @example
 * ```javascript
 * const merkleProof = calculateSPVMerkleRoot(
 *   '7e0ba1980522125f1f40d19a249ab3ae036001b991776813d25aebe08e8b8a50',
 *   [
 *     "c1d32f28baa27a376ba977f6a8de6ce0a87041157cef0274b20bfda2b0d8df96",
 *     "7e0ba1980522125f1f40d19a249ab3ae036001b991776813d25aebe08e8b8a50",
 *     "5c4d44b9b8d2ec6e0835ac90f206cecb26bf51033f31d4c659975b7534853409"
 *   ]
 * );
 * ```
 * @name calculateMerkleProof
 * @function
 * @param {string} txid
 * @param {Array} hashes
 * @return {Object}
 */
function calculateMerkleProof(txid, hashes) {
    if(hashes.length === 0) {
        return {
            txid: txid,
            pos: 0,
            merkle: [txid]
        }
    }
    let merkle = calculateMerkleTree(hashes);
    let proof = {
        txid: txid,
        pos: hashes.indexOf(txid),
        merkle: []
    };
    calculatePairs(proof.pos, merkle.tree.length).forEach((n,j) => {
    		proof.merkle.push((merkle.tree[j][n]) ? merkle.tree[j][n] : merkle.tree[j][n-1]); 
    });
    return proof;
}

 /**
 * Calculate the merkle tree of a block from an array of its TXIDs
 * 
 * @example
 * ```javascript
 * const merkleTree = calculateMerkleTree(
 *   [
 *     "c1d32f28baa27a376ba977f6a8de6ce0a87041157cef0274b20bfda2b0d8df96",
 *     "7e0ba1980522125f1f40d19a249ab3ae036001b991776813d25aebe08e8b8a50",
 *     "5c4d44b9b8d2ec6e0835ac90f206cecb26bf51033f31d4c659975b7534853409"
 *   ]
 * );
 * ```
 * @name calculateMerkleTree
 * @function
 * @param {Array} hashes
 * @return {Object}
 */
function calculateMerkleTree(hashes){
    if(hashes.length === 1){
    	return {
      	merkleRoot: hashes[0],
      	tree: [hashes[0]]
      };
    }
    let layers = [hashes.map(h => bsv.deps.Buffer.from(h, 'hex').reverse())];
    while(layers[layers.length-1].length>1){
        let layer = [];
        for(let i=0; i<layers[layers.length-1].length; i+=2){
            if(layers[layers.length-1][i]){
                const pair = layers[layers.length-1][i+1] ? [layers[layers.length-1][i], layers[layers.length-1][i+1]] : [layers[layers.length-1][i], layers[layers.length-1][i]];
                layer.push(bsv.crypto.Hash.sha256sha256(bsv.deps.Buffer.concat(pair)));
            }
        }
        layers.push(layer);
    }
    return {
    	merkleRoot: layers.pop()[0].reverse().toString('hex'),
      tree: layers.map(l => l.map(h => h.reverse().toString('hex')))
    };
}

 /**
 * Calculate pair indexes from index of TX and number of layers below merkle root
 * 
 * @example
 * ```javascript
 * const pairs = calculatePairs(
 *   12,
 *   7
 * );
 * ```
 * @name calculatePairs
 * @function
 * @param {number} pos
 * @param {number} layers
 * @return {Object}
 */
function calculatePairs(pos, layers){
    let pairs = [];
    let rpos = pos;
    for(let i = 0; i<layers; i++){
        pairs.push((rpos%2===0) ? rpos+1 : rpos-1);
        rpos = Math.floor(rpos/(2));
    }
    return pairs;
}

 /**
 * Calculate all merkle proofs for all transactions in a block from
 * an array of all of its TXIDs
 * 
 * @example
 * ```javascript
 * const merkleProofs = calculateAllMerkleProofs(
 *   [
 *     "c1d32f28baa27a376ba977f6a8de6ce0a87041157cef0274b20bfda2b0d8df96",
 *     "7e0ba1980522125f1f40d19a249ab3ae036001b991776813d25aebe08e8b8a50",
 *     "5c4d44b9b8d2ec6e0835ac90f206cecb26bf51033f31d4c659975b7534853409"
 *   ]
 * );
 * ```
 * @name calculateAllMerkleProofs
 * @function
 * @param {Array} hashes
 * @return {Object}
 */
function calculateAllMerkleProofs(hashes) {
    let merkle = calculateMerkleTree(hashes);
    let proofs = {
        merkleRoot: merkle.merkleRoot,
        txs: []
    };
    merkle.tree[0].forEach((tx, i) => {
        let proof = {
            txid: tx,
            pos: i,
            merkle: []
        };
        calculatePairs(i, merkle.tree.length).forEach((n,j) => {
            proof.merkle.push((merkle.tree[j][n]) ? merkle.tree[j][n] : merkle.tree[j][n-1]);
        });
        proofs.txs.push(proof);
    });
    return proofs;
}