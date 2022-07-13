import process from 'process';
import { createRequire } from 'module';
import {createPatriciaMerkleTree,CryptoSHAValue} from './createPatriciaMerkleTree.js'
import { SecureTrie as Trie } from 'merkle-patricia-tree'// We import the library required to create a Secure Merkle Patricia Tree
const require = createRequire(import.meta.url);
const util = require('util');
const SHA256 = require('crypto-js/sha256')
const SHA512 = require('crypto-js/sha512')
const SHA3 = require('crypto-js/sha3')
const { MerkleTree } = require('merkletreejs')
const zlib = require('zlib')

let crypto;
var config =require('../config.json');

crypto = require('crypto');

export const verifyAttributes = async (VCs, VP)  => {
    var listHashedKey =[]
    var listProofDecompress =[]
    let listValue= VP.vp.attributes
    const listProof = VP.vp.proof
    // console.log("lato verificatore")
    for(const credential of VCs){
        var credVC = credential.credentialSubject
        var root = credVC["root"] // nodo radice della VC

        for(let i=0; i<listValue.length;i++){
            let buf = Buffer.from(listProof[i].listPathNodesComp,'base64')
            // console.log(buf)
            let decompression = zlib.brotliDecompressSync(buf) //1. decompressione Proof
            // console.log("proof buffer dopo decompressione brot")
            // console.log(decompression)
            // console.log("JSON to obj")
            let obj= JSON.parse(decompression) //2. trasformo json in oggetto
             // console.log(obj)

            for(let i=0 ; i<obj.length; i++) {
                // console.log(Buffer.from(obj[i]))
                listProofDecompress[i] = Buffer.from(obj[i]) // trasformo la proof in array di buffer
            }
            // console.log("listProofDecompress")
            // console.log(listProofDecompress)
            // console.log("FINE")
            let keyAttr= listProof[i].name
            let tmp=listValue[i].split(":") // ricavo il valore i-esimo corrispondente alla chiave i-esima
            let value=tmp[1]
            let objHashed=  await CryptoSHAValue(value,listProof[i].nonceValue) //// applico l'hashing + nonce al valore per verificarla
          /*  console.log("valore HASHATO " + i)
            console.log(objHashed.hashedValue)*/
            try{
                let val = await Trie.verifyProof(Buffer.from(root), Buffer.from(keyAttr), listProofDecompress) // verifica del nodo
                if(objHashed.hashedValue==val) {
                    // console.log(Buffer.from(objHashed.hashedValue))
                    // console.log(val)
                    // console.log("Il valore dell'attributo verificato è: " + value)
                }
                else{
                    console.log("Verifica fallita!")
                }
            }
            catch (e) {
                console.log("Verifica dell'attributo " + keyAttr +" fallita ")
            }
        }

/*        for(let i=0;i<listProof.length;i++){ // verifica di tutti gli attributi presenti nella VP
             console.log("sono la proof in formato string")
             console.log(listProof[i].listPathNodesComp)
              //listProof[i].listPathNodesComp = convertToBufferBase64(listProof[i].listPathNodesComp) // converte i nodi della proof da string a buffer
            let buf= Buffer.from(listProof[i].listPathNodesComp,'base64') // converto la proof da string a buffer
             console.log("ora sono un buffer in base 64")
             console.log(buf)
             let decompression = zlib.brotliDecompressSync(buf) // decompressione

            // console.log("FINE")
            let keyAttr= listProof[i].name
            let obj=  await CryptoSHAKey(keyAttr,listProof[i].nonceKey) //// applico l'hashing + nonce alla chiave per verificarla
                
            try{
                 let val = await Trie.verifyProof(Buffer.from(root), Buffer.from(obj.hashedKey), listProof[i].listPathNodes) // verifica del nodo
                 // console.log("Il valore dell'attributo verificato è: " + val.toString())
            }
            catch (e) {
                console.log("Verifica dell'attributo " + keyAttr +" fallita ")
            }
        }*/
    }

    return ;
}

//Metodo che converte i nodi della proof da string a buffer
export const convertToBufferBase64= (list) =>{
    let proof = []
    for(let elem of list) {
        proof.push(Buffer.from(elem,'base64'))
    }

    return proof
}


