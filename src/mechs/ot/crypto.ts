/*
* This file implements the real crypto actions
* that are needed for OT. It uses the node crypto
* available methods, selecting special cases from
* user choice of ot provider.
*/

//import crypto from "crypto";
import * as crypto from 'crypto'
//const crypto = require('crypto');
import bigInt from 'big-integer';
import { Utils } from "./utils";
//import * as core from "webcrypto-core";
//import { AlgorithmIdentifier } from '../../asn';

//TODO: This interface will be moved
interface OtDHParams extends Algorithm {
    isSender?: boolean,
    m?: number,
    n?: number,
    privateKey?: CryptoKey,
    publicKey?: CryptoKey,
    prime?: number;
}

//TESTING: Temporal interface to test DH Keys
class DHKey implements CryptoKey{
    public data!: Buffer;
    public algorithm!: KeyAlgorithm;
    public extractable!: boolean;
    public type!: KeyType;
    public usages!: KeyUsage[];
}
class DHKeyPair implements CryptoKeyPair{
    public publicKey!: CryptoKey;
    public privateKey!: CryptoKey;
}

export class OtCrypto {

    /******************* GENERATEKEYPAIR *******************************/

    // Method to generate a KeyPair - partially tested
    // Needs core implementation
    public static async generateKeyPair(algorithm: Algorithm): Promise<CryptoKeyPair> {
        switch (algorithm.name.toUpperCase()){
            case "OT-SIMPLEST-1OUT2":
                return this.generateDHKeyPair(algorithm);
            default:
                //throw new core.OperationError("algorithm: Is not recognized");
                throw new Error('algorithm: Is not recognized');
        }
    }

    // Method for generating a DHKeyPair - not tested
    public static async generateDHKeyPair(algorithm: OtDHParams) {
        if(algorithm.prime == undefined){
            var dh = crypto.createDiffieHellman(1024);  //TODO: Consider other lengths
        }else{
            var dh = crypto.createDiffieHellman(algorithm.prime.toString(16), 'hex');    
        }
        const dhAgent = dh;
        const publicKey: DHKey = new DHKey();
        publicKey.data = Buffer.from(dhAgent.generateKeys());  //TODO: Check Buffer instantiation
        const privateKey: DHKey = new DHKey();
        privateKey.data = Buffer.from(dhAgent.getPrivateKey());    //TODO: Check Buffer instantiation
        //TOCHECK: key.algorithm has not been declared
        const kp: DHKeyPair = new DHKeyPair();
        kp.publicKey = publicKey;
        kp.privateKey = privateKey;
        return kp;
    }

    /*******************************************************************/ 

    /**************** OPERATIONS WITH DH KEYS **************************************/

    // Method to multiply two DH public keys with format conversions
    // Needs core implementation
    public static async multiplyDHKeys(hexKeyA: string, hexKeyB: string, module: BigInt): Promise<string> {
        const numbKeyA = bigInt(hexKeyA, 16);
        const numbKeyB = bigInt(hexKeyB, 16);
        const AB = numbKeyA.multiply(numbKeyB).mod(bigInt(module.toString(16), 16));
        const hexAB = AB.toString(16);
        return hexAB;
    } 

    public static async divideDHKeys(hexKeyA: string, hexKeyB: string, module: BigInt): Promise<string> {
        const numbKeyA = bigInt(hexKeyA, 16);
        const numbKeyB = bigInt(hexKeyB, 16);
        const p = bigInt(module.toString(16), 16);
        const invNumbKeyB = numbKeyB.modInv(p);
        const res = numbKeyA.multiply(invNumbKeyB).mod(p).toString(16);
        return res;
    }

    /*******************************************************************/

    /*********************** KEY DERIVATION ******************************/
    public static async simmetricKeyDerivation(publicKey: string, privateKey: string, module: BigInt): Promise<string>{
        const numbPublicKey = bigInt(publicKey, 16);
        const numbPrivateKey = bigInt(privateKey, 16);
        const powKey = Utils.modPow(BigInt(numbPublicKey), BigInt(numbPrivateKey), module);
        const hexPowKey = powKey.toString(16);
        const hash = crypto.createHash('sha256');
        hash.update(hexPowKey);
        const hexCipherKey = hash.digest();
        return hexCipherKey.toString('hex');
    }

    /*******************************************************************/

    public static async cipherMessage(key: string, message: string): Promise<string> {

        const cipher = crypto.createCipheriv('aes256', key, Buffer.allocUnsafe(16));

        let encrypted = cipher.update(message, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        return encrypted;
    }

}

/****************
* TESTING ZONE
*****************/
/*
let alg:OtDHParams = {
    name: 'OT-SIMPLEST-1OUT2',
    isSender: true,
    n: 100
};
OtCrypto.generateKeyPair(alg)
.then(function(keyPair){
    console.log(keyPair);
})
.catch(function(err){
    console.error(err);
});
*/