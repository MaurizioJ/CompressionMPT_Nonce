import Resolver from 'did-resolver'
import getResolver from 'ethr-did-resolver'
import { EthrDID } from 'ethr-did'
import { ethers } from 'ethers'
import { computePublicKey } from '@ethersproject/signing-key'
//import { ES256KSigner } from 'did-jwt'
import pkg, { verifyCredential, normalizeCredential, validateCredentialPayload } from 'did-jwt-vc';
const { createVerifiableCredentialJwt, createVerifiablePresentationJwt, verifyPresentation } = pkg;
import bip39 from 'bip39'
import { createRequire } from 'module';
import {createPatriciaMerkleTree} from './createPatriciaMerkleTree.js'
import {verifyAttributes, convertToBufferBase64} from './verifyAttributesPatricia.js'
const require = createRequire(import.meta.url);
var config =require('../config.json');
const hdkey = require('ethereumjs-wallet/hdkey')
const didJWT = require('did-jwt');
const zlib = require('zlib')

import { SecureTrie as Trie } from 'merkle-patricia-tree'
import file from "fs";
// We import the library required to create a Secure Merkle Patricia Tree

const { performance } = require('perf_hooks'); // performance suite for time measurement
var disclosure= {};


const mnemonic = 'family dress industry stage bike shrimp replace design author amateur reopen script';

//function that retrieves private keys of Truffle accounts
// return value : Promise
const getTrufflePrivateKey = (mnemonic, index) => {
    if (index < 0 || index > 9) throw new Error('please provide correct truffle account index')
    return bip39.mnemonicToSeed(mnemonic).then(seed => {
        const hdk = hdkey.fromMasterSeed(seed);
        const addr_node = hdk.derivePath(`m/44'/60'/0'/0/${index}`); //m/44'/60'/0'/0/0 is derivation path for the first account. m/44'/60'/0'/0/1 is the derivation path for the second account and so on
        //const addr = addr_node.getWallet().getAddressString(); //check that this is the same with the address that ganache list for the first account to make sure the derivation is correct
        const privKey = addr_node.getWallet().getPrivateKey();
        return privKey;
    }).catch(error => console.log('getTrufflePrivateKey ERROR : ' + error));
}

async function createVCPayload(user,nClaims) {
    const VCPayload={};
    var credAttrName =[];
    var credAttrValue =[];
    //VCPayload['sub']=user.did;
    //VCPayload['nbf']=626105238;
    VCPayload['vc']= {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential'],
        credentialSubject: {},
    };
    for (let i = 0; i < nClaims; i++) {
        var attrName="attrName"+i;
        var attrValue="attrValue"+i;
        credAttrName.push(attrName)
        credAttrValue.push(attrValue)
    }
    const newPatriciaMerkleTree = await createPatriciaMerkleTree(credAttrName,credAttrValue); // (attributi da criptare) --> restituisce un oggetto contenente (path nodi per proof, root del merkle tree}
    VCPayload['vc']['credentialSubject']['root']= newPatriciaMerkleTree.root; // si salva la root del merkle Patricia tree
    disclosure={ clearKeyList:credAttrName, clearValueList: credAttrValue, proof:newPatriciaMerkleTree.proof, nonce:newPatriciaMerkleTree.nonce} // utile per quando farò la disclosure delle claims nella VP

    return VCPayload;
}
function createVPPayload(vc,nClaims) {
    const VCPayload={};
    VCPayload['vp']= {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiablePresentation'],
        verifiableCredential: [vc]
    };

    VCPayload['vp']['attributes']=[]; // qui andranno gli attributi da svelare fatti così attrName0:attrValue0...
    VCPayload['vp']['proof']=[]

    if (nClaims===disclosure.clearKeyList.length) { // caso in cui devo rivelare tutti gli attributi
        for(let i=0;i<disclosure.clearKeyList.length;i++){
            VCPayload['vp']['attributes'].push(disclosure.clearKeyList[i]+":"+disclosure.clearValueList[i]) // inserisco le claims che voglio svelare
            let name =disclosure.clearKeyList[i]
            let listPathNodes=disclosure.proof[name] // inserisco in listPathNodes il path completo dei nodi utili per ottenere la radice (proof)
            // console.log("PROOF:")
            // console.log(disclosure.proof[name])
            let proofJs= JSON.stringify(listPathNodes) // 1. trasformo l'array contenente buffer in JSON
            // console.log("JSON proof")
            // console.log(proofJs)
            let buf = Buffer.from(proofJs)
             // console.log("proof buffer prima della compressione")
             // console.log(buf)
             // console.log(memorySizeOf(buf))
            //  let proofJs=Buffer.from(JSON.stringify(listPathNodes))
             //console.log(proofJs)
             // console.log("proof buffer dopo la compressione con algoritmo brotli")
            let listPathNodesComp = zlib.brotliCompressSync(buf) //2. applicazione algoritmo di compressione sulla proof
            // console.log(listPathNodesComp)
            // console.log(memorySizeOf(listPathNodesComp))
            // console.log("proof come stringa per compatibilità JWT")
             listPathNodesComp=listPathNodesComp.toString('base64') //3. per renderlo compatibile col formato jwt
            // console.log(memorySizeOf(listPathNodesComp))
            /*console.log(listPathNodesDecComp)
             let buf1 = Buffer.from(listPathNodesDecComp,'base64')
            // console.log(buf)
            let decompression = zlib.brotliDecompressSync(buf1) //
            console.log("proof buffer dopo decompressione brot")
           console.log(decompression)
            console.log("JSON to obj")
            let objJSON= JSON.parse(decompression) //4. trasformo json in oggetto
            console.log(objJSON)
            return ;*/
            // console.log("dopo compressione")
            //  console.log(listPathNodesComp)
            // listPathNodesComp= listPathNodes.toString('base64') // view a string per compatibilità con jwt
            // console.log("PROVAAAAA")
            //  console.log(listPathNodesComp)

            // console.log(listPathNodesComp)
            let nonceValue = disclosure.nonce[name]
            let obj=  {name , listPathNodesComp, nonceValue}
            VCPayload['vp']['proof'].push(obj) // inserisco nella lista l'oggetto formato dal valore in chiaro e la proof per quel valore
            
        }
    }
   else{ // prendo attributi a caso, se il numero di claims da rivelare != dal numero di attributi totali

        for (let i = 0; i < nClaims; i++) {
            const size= disclosure.clearValueList.length - 1
            const rand = Math.random()
            let i = Math.floor(size * rand) // indice dell'attributo selezionato random
            VCPayload['vp']['attributes'].push(disclosure.clearKeyList[i]+":"+disclosure.clearValueList[i]) // inserisco il valore in chiaro del nodo foglia
            let name =disclosure.clearKeyList[i]
            let listPathNodes=disclosure.proof[name] // inserisco in listPathNodes il path completo dei nodi utili per ottenere la radice (proof)
            let proofJs=JSON.stringify(listPathNodes) // 1. trasformo l'array contenente buffer in JSON
            let buf = Buffer.from(proofJs)
            // console.log("proof buffer prima della compressione")
            // console.log(buf)
            // console.log("proof buffer dopo la compressione con algoritmo brotli")
            let listPathNodesComp = zlib.brotliCompressSync(buf) //2. applicazione algoritmo di compressione sulla proof
            // console.log(listPathNodesComp)
            // console.log("proof come stringa per compatibilità JWT")
            listPathNodesComp=listPathNodesComp.toString('base64') //3. per renderlo compatibile col formato jwt
            let nonceValue = disclosure.nonce[name]
            let obj=  {name , listPathNodesComp, nonceValue}
            VCPayload['vp']['proof'].push(obj) // inserisco nella lista l'oggetto formato dal valore in chiaro e la proof per quel valore

        }
    }

    return VCPayload;
}

//setup the provider
console.log('Connecting to provider...');
const Web3HttpProvider = require('web3-providers-http')
// ...
const web3provider = new Web3HttpProvider('http://localhost:9545')
const provider = new ethers.providers.Web3Provider(web3provider, 'any')
//const provider = new ethers.providers.JsonRpcProvider('http://localhost:9545');

// get accounts provided by Truffle, with respective private keys


console.log('Connected to the provider');
//contract address of the registry
const RegAddress = '0x1482aDFDC2A33983EE69F9F8e4F852c467688Ea0';

//function where the creation of an identity will be tested
const test = async (accounts) => {
    const fs = require('fs')

    // create DID of the interacting subjects
    const uni = await createDid(RegAddress, accounts[0], 0);
    
    const PaoloMori = await createDid(RegAddress, accounts[1], 1);


    // create the DID resolver
    const ethrDidResolver = getResolver.getResolver(
        {
            rpcUrl: 'http://localhost:9545',
            registry: RegAddress,
            chainId:   '0x539',
            provider
        }
    );
    const didResolver = new Resolver.Resolver(ethrDidResolver);



    const options = {
        header: {
            "typ": "JWT",
            "alg": "ES256K"
        },
    };

    // create VC issued by university to Paolo Mori
    let vcCreationTimes=[];
let j=1
    console.log("-------------------------------------------------------------------------")
    for (let i = j; i <j+1; i++) {
        let res = 0.0;
        let jwtP;
        let jwtSize = 0;
        console.log("Numero totale di attributi criptati della VC: " + Math.pow(2, i));
        const VCPayload = await createVCPayload(PaoloMori, Math.pow(2, i));
        const jwt = await createVerifiableCredentialJwt(VCPayload, uni, options);

        var soglia = config.merklePatriciaTree.soglia;
        let nCl= Math.ceil(Math.pow(2,i)*soglia); // claims da rivelare
        if(Math.pow(2, i)< nCl) {
            console.log( "Attenzione! Numero di claims da rivelare superiore al numero di attributi presenti nella VC ");
            return ;
        }
        console.log("Numero attributi della VP da svelare: " + nCl)
        const VPPayload = createVPPayload(jwt,nCl); // nClaims indica il numero di claims che voglio che siano rivelate
        jwtP=await createVerifiablePresentationJwt(VPPayload,PaoloMori,options);
        console.log("Verifica della VP in corso...")
        for (let j = 0; j <1; j++) {
           let start = performance.now();
                 const verifiedPresentation= await verifyPresentation(jwtP, didResolver,options);
                 const unverifiedVCs= verifiedPresentation.verifiablePresentation.verifiableCredential;
                const verifiedVP= verifiedPresentation.verifiablePresentation;
                 const verifyAtt = await verifyAttributes(unverifiedVCs,verifiedVP); // verifica delle claims della VP
            let end = performance.now();
            const createVCtime = (end-start);
            // const signedVC = await createVCPerformance(VCPayload, uni, options);
            res = res + createVCtime;
            // jwtSize = jwtSize + memorySizeOf(jwt);
            //console.log(signedVC.time);
        }
        vcCreationTimes.push([res/config.merklePatriciaTree.iterations]);
        console.log("-------------------------------------------------------------------------")

    }

    console.log(vcCreationTimes);

    var file = require('fs');

    file.appendFile('test_Verification_VP'+soglia+'_NOcomp.txt', Math.pow(2,j) + ' ' + vcCreationTimes + '\n', function (err) {
        if (err) throw err;
        console.log('soglia al %'+ soglia);
    });


}

//function to create and return the object used to manage a DID
const createDid = async (RegAddress, accountAddress, index, chainId = '0x539') => {
    return getTrufflePrivateKey(mnemonic, index)
        .then(privateKey => {
            const publicKey = computePublicKey(privateKey, true);
            const uncompressedPublicKey = computePublicKey(privateKey, false);
            /* console.log(publicKey);
             console.log(uncompressedPublicKey);
             console.log(privateKey);*/
            const identifier = `did:ethr:${chainId}:${publicKey}`;
            const signer = provider.getSigner(index);
            //const signJ=didJWT.SimpleSigner(privateKey);
            //const signJ=didJWT.EllipticSigner(privateKey);

            //const signJ=didJWT.EdDSASigner(privateKey);
            const signJ=didJWT.ES256KSigner(privateKey,false);
            const conf = {
                //txSigner: signer,
                //privateKey : privateKey,
                signer: signJ,
                identifier: identifier,
                registry: RegAddress,
                chainNameOrId: chainId,
                provider
            };
            return new EthrDID(conf);
        })
}



const createVCPerformance = async (payload, did, options) => {
    let start = performance.now();
    const jwt = await createVerifiableCredentialJwt(payload, did, options);
    let end = performance.now();
    const createVCtime = (end-start);
    return {res : jwt, time : createVCtime};
}
const createVPPerformance =  async (payload, did, options) => {
    let start = performance.now();
    const jwt = await createVerifiablePresentationJwt(payload, did, options);
    let end = performance.now();
    const createVPtime = "Create VP took " + (end-start) + "ms"
    return {res : jwt, time : createVPtime} ;
}

const verifyPresentationPerformance = async (jwt, resolver) => {
    let start = performance.now();
    const result = await verifyPresentation(jwt, resolver);
    let end = performance.now();
    const verifyVPtime = "Verify VP took " + (end-start) + "ms"
    return {res : result, time : verifyVPtime};
}

const verifyCredentialPerformance = async (jwt, didResolver) => {
    let start = performance.now();
    //const result = await verifyCredential(jwt, resolver);
    let verificationResponse = await didJWT.verifyJWT(jwt,{resolver:didResolver});
    let end = performance.now();
    const verifyVCtime = "Verify VC took " + (end-start) + "ms"
    return {res : verificationResponse, time : verifyVCtime};
}

//actual function that starts executing and this will invoke all the other pieces of code

provider.listAccounts().then((accounts) => {
    test(accounts).catch(error => console.log(error));
    //getTrufflePrivateKey(mnemonic,0).then(res => console.log(res.toString('hex')));
});


function memorySizeOf(obj) {
    var bytes = 0;

    function sizeOf(obj) {
        if(obj !== null && obj !== undefined) {
            switch(typeof obj) {
                case 'number':
                    bytes += 8;
                    break;
                case 'string':
                    bytes += obj.length * 2;
                    break;
                case 'boolean':
                    bytes += 4;
                    break;
                case 'object':
                    var objClass = Object.prototype.toString.call(obj).slice(8, -1);
                    if(objClass === 'Object' || objClass === 'Array') {
                        for(var key in obj) {
                            if(!obj.hasOwnProperty(key)) continue;
                            sizeOf(obj[key]);
                        }
                    } else bytes += obj.toString().length * 2;
                    break;
            }
        }
        return bytes;
    };

    function formatByteSize(bytes) {
        if(bytes < 1024) return bytes + " bytes";
        else if(bytes < 1048576) return(bytes / 1024).toFixed(3) + " KiB";
        else if(bytes < 1073741824) return(bytes / 1048576).toFixed(3) + " MiB";
        else return(bytes / 1073741824).toFixed(3) + " GiB";
    };

    return sizeOf(obj);
};
