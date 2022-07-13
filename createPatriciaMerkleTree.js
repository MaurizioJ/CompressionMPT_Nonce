import process from 'process';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
var config =require('../config.json');
let crypto = require('crypto');
const util = require('util');
const { MerkleTree } = require('merkletreejs')
const SHA256 = require('crypto-js/sha256')
const SHA512 = require('crypto-js/sha512')
const SHA3 = require('crypto-js/sha3')
const generateKey = util.promisify(crypto.generateKey);
// const generateKey = util.promisify(crypto.generateKey);
import { SecureTrie as Trie } from 'merkle-patricia-tree'// We import the library required to create a Secure Merkle Patricia Tree


const {createHash} = await import('node:crypto');

let h = await crypto.getHashes();
// console.log("Available hash algorithms..");
// console.log(h);

export const CryptoSHAValue = async (node,key = undefined) => {
    if (!key){ // genero un nonce casuale
        key = crypto.randomBytes(config.merklePatriciaTree.keyLength).toString('base64'); // creazione del nonce
    }

    const hash = createHash(config.merklePatriciaTree.H);
    hash.update(node)
    let hashedValue = hash.digest('hex')

    return {hashedValue:hashedValue+key,nonce:key} //concateno un nonce generato random alla fine della foglia
}

export const createPatriciaMerkleTree = async (credAttrName, credAttrValue) => {
    var trie = await new Trie()
    var proof =[]
    var keyHashed =[]
    var nonce ={}
    let obj ={}
    // Inserisco le coppie key:value nel trie
   for(let i=0;i<credAttrValue.length;i++){
       obj=await CryptoSHAValue(credAttrValue[i]) //return hashing del valore + nonce
      /* console.log("valore HASHATO" +i)
       console.log(obj.hashedValue)*/
       nonce[credAttrName[i]] = obj.nonce // memorizzo il nonce della chiave
       // keyHashed.push(obj.hashedValue) // lista delle chiavi hashate + nonce
       await trie.put(Buffer.from(credAttrName[i]), Buffer.from(obj.hashedValue)) // inserisco nel Trie la coppia <keccak256(key),valueHashed>
   }
   // creo la proof per ogni coppia e la converto nel formato string
   for(let i=0; i<credAttrName.length; i++){
        proof[credAttrName[i]]=(await Trie.createProof(trie,Buffer.from(credAttrName[i]))) // creo la proof
        // proof[credAttrName[i]]=convertToString(proof[credAttrName[i]]) // converte i nodi della proof in string per compatibilità col jwt
   }
   return {root:trie.root , proof: proof, nonce:nonce}
}

// Metodo che converte ogni nodo della lista proof da buffer a string per renderlo compatibile con formato jwt
const convertToString = (list) =>{ // input lista dei nodi
    let proof = []
    for(let elem of list) {
        proof.push(elem.toString('base64'))
    }
    return proof
}
