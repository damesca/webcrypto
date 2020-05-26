/*
* This file implements the real crypto actions
* that are needed for OT. It uses the node crypto
* available methods, selecting special cases from
* user choice of ot provider.
*/

import * as crypto from 'crypto'
import bigInt from "big-integer";
import { Utils } from "./utils";
import * as core from "webcrypto-core";
import { CryptoKey } from "../../keys/key";
import * as asn from "../../asn";
import { RsaPrivateKey } from "../rsa/private_key";
import { RsaPublicKey } from "../rsa/public_key";
import { AsnParser, AsnSerializer } from "@peculiar/asn1-schema";
import { JsonParser, JsonSerializer } from "@peculiar/json-schema";

export class OtCrypto {

    /********************** RAW RSA ************************/

    // Reverse a buffer into inverse order
    private static reverse(buffer: Buffer): Buffer{
        var result = Buffer.alloc(buffer.length);
        var j = buffer.length - 1;
        for(var i = 0; i < buffer.length; i++){
            result[i] = buffer[j];
            j--;
        }
        return result;
    }

    // Converts Octet String (Buffer) into BigInt
    public static os2ip(buffer: Buffer): bigInt.BigInteger {
        const xLen = buffer.length;
        const revBuff = this.reverse(buffer);
        var x = bigInt(0);
        var sum = bigInt(0);
        for(var i = 0; i <= xLen; i++){
            var dataBuff = bigInt(revBuff[i]);
            var dataPow = bigInt(256).pow(i);
            sum = dataBuff.multiply(dataPow);
            x = x.add(sum);
        }
        return x;
    }

    // Converts BigInt into Octet String (Buffer) of given length (xLen)
    public static i2osp(x: bigInt.BigInteger, xLen: number): Buffer {
        if(xLen <= 0){
            throw new Error('Error: Invalid xLen');
        }
        const comparison = x.compare(bigInt(256).pow(xLen));
        if(comparison == 1 || comparison == 0){
            console.log("\nInteger too large: " + x.toString());
            throw new Error('Error: Integer too large');
        }
        var digits = Buffer.alloc(xLen);
        var j = 0;
        do{
            var comp = x.compare(0);
            digits[j] = (x.mod(256)).valueOf();
            x = x.divide(256);
            j++;
        }while(comp != 0);
        for(var i = j; i <= xLen; i++){
            digits[i] = 0;
        }
        return this.reverse(digits);
    }

    public static rawRsaEncrypt(modulus: Buffer, publicExponent: Buffer, message: Buffer, cipherLength: number = 0): Buffer {
        var maxLen = modulus.length;
        const n = this.os2ip(modulus);
        const e = this.os2ip(publicExponent);
        const m = this.os2ip(message);
        console.log("\n[%%%] RAWRSAENCRYPT");
        console.log("\n[bigint]n: " + n.toString());
        console.log("\n[bigint]e: " + e.toString());
        console.log("\n[bigint]m: " + m.toString());

        // TODO: public key (n, e) checking

        // Checking: m is greater than n-1 or lesser than 0
        if(m.compare(n.minus(1)) == 1 || m.compare(0) == -1){
            throw new Error('Error: message representative out of range');
        }

        const c = m.modPow(e, n);
        console.log("\n[bigint]c(return): " + c.toString());
        if(cipherLength != 0)
            maxLen = cipherLength;
        const cipherText = this.i2osp(c, maxLen);

        return cipherText;
    }

    public static rawRsaDecrypt(modulus: Buffer, privateExponent: Buffer, cipherText: Buffer, messageLength: number): Buffer {
        const maxLen = modulus.length;
        const n = this.os2ip(modulus);
        const d = this.os2ip(privateExponent);
        const c = this.os2ip(cipherText);
        console.log("\n[%%%] RAWRSADECRYPT");
        console.log("\n[bigint]n: " + n.toString());
        console.log("\n[bigint]d: " + d.toString());
        console.log("\n[bigint]c: " + c.toString());

        // TODO: private key (n, d) checking

        // Checking: c is greater than n-1 or lesser than 0
        if(c.compare(n.minus(1)) == 1 || c.compare(0) == -1){
            throw new Error('Error: cipherText representative out of range');
        }

        var m = c.modPow(d, n);
        console.log("\n[bigint]m(return): " + m.toString());
        /////  TEMPORAL FIX - NOT PROPER SECURITY //////
        const comparison = m.compare(bigInt(256).pow(messageLength));
        if(comparison == 1 || comparison == 0){
            m = bigInt.randBetween(0, bigInt(256).pow(messageLength));
        }
        /*********************************************/
        const message = this.i2osp(m, messageLength);

        return message;
    }

    public static rsaEncrypt(publicKey: crypto.RsaPublicKey, message: Buffer): Buffer {
        return crypto.publicEncrypt(publicKey, message); 
    }

    public static rsaDecrypt(privateKey: crypto.RsaPrivateKey, ciphertext: Buffer): Buffer {
        return crypto.privateDecrypt(privateKey, ciphertext);
    }

    /*******************************************************/

    /********************** KEY MANAGEMENT *****************************/

    public static async exportKey(format: KeyFormat, key: CryptoKey): Promise<JsonWebKey | ArrayBuffer> {
        switch (format.toLowerCase()) {
          case "jwk":
            return JsonSerializer.toJSON(key);
          case "pkcs8":
          case "spki":
            return new Uint8Array(key.data).buffer;
          default:
            throw new core.OperationError("format: Must be 'jwk', 'pkcs8' or 'spki'");
        }
    }

    public static async importKey(format: KeyFormat, keyData: JsonWebKey | ArrayBuffer, algorithm: RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKey> {
        switch (format.toLowerCase()) {
          case "jwk":
            const jwk = keyData as JsonWebKey;
            if (jwk.d) {
              const asnKey = JsonParser.fromJSON(keyData, { targetSchema: asn.RsaPrivateKey });
              return this.importPrivateKey(asnKey, algorithm, extractable, keyUsages);
            } else {
              const asnKey = JsonParser.fromJSON(keyData, { targetSchema: asn.RsaPublicKey });
              return this.importPublicKey(asnKey, algorithm, extractable, keyUsages);
            }
          case "spki": {
            const keyInfo = AsnParser.parse(new Uint8Array(keyData as ArrayBuffer), asn.PublicKeyInfo);
            const asnKey = AsnParser.parse(keyInfo.publicKey, asn.RsaPublicKey);
            return this.importPublicKey(asnKey, algorithm, extractable, keyUsages);
          }
          case "pkcs8": {
            const keyInfo = AsnParser.parse(new Uint8Array(keyData as ArrayBuffer), asn.PrivateKeyInfo);
            const asnKey = AsnParser.parse(keyInfo.privateKey, asn.RsaPrivateKey);
            return this.importPrivateKey(asnKey, algorithm, extractable, keyUsages);
          }
          default:
            throw new core.OperationError("format: Must be 'jwk', 'pkcs8' or 'spki'");
        }
    }

    protected static importPrivateKey(asnKey: asn.RsaPrivateKey, algorithm: RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[]) {
        const keyInfo = new asn.PrivateKeyInfo();
        keyInfo.privateKeyAlgorithm.algorithm = "1.2.840.113549.1.1.1";
        keyInfo.privateKeyAlgorithm.parameters = null;
        keyInfo.privateKey = AsnSerializer.serialize(asnKey);
    
        const key = new RsaPrivateKey();
        key.data = Buffer.from(AsnSerializer.serialize(keyInfo));
    
        key.algorithm = Object.assign({}, algorithm) as RsaHashedKeyAlgorithm;
        key.algorithm.publicExponent = new Uint8Array(asnKey.publicExponent);
        key.algorithm.modulusLength = asnKey.modulus.byteLength << 3;
        key.extractable = extractable;
        key.usages = keyUsages;
    
        return key;
        
    }

    protected static importPublicKey(asnKey: asn.RsaPublicKey, algorithm: RsaHashedImportParams, extractable: boolean, keyUsages: KeyUsage[]) {
        const keyInfo = new asn.PublicKeyInfo();
        keyInfo.publicKeyAlgorithm.algorithm = "1.2.840.113549.1.1.1";
        keyInfo.publicKeyAlgorithm.parameters = null;
        keyInfo.publicKey = AsnSerializer.serialize(asnKey);
    
        const key = new RsaPublicKey();
        key.data = Buffer.from(AsnSerializer.serialize(keyInfo));
    
        key.algorithm = Object.assign({}, algorithm) as RsaHashedKeyAlgorithm;
        key.algorithm.publicExponent = new Uint8Array(asnKey.publicExponent);
        key.algorithm.modulusLength = asnKey.modulus.byteLength << 3;
        key.extractable = extractable;
        key.usages = keyUsages;
    
        return key;
    }

    /*******************************************************************/

    /******************* GENERATEKEYPAIR *******************************/

    // Method to generate a KeyPair - partially tested
    // Needs core implementation
    /*
    public static async generateKeyPair(algorithm: Algorithm): Promise<CryptoKeyPair> {
        switch (algorithm.name.toUpperCase()){
            case "OT-SIMPLEST-1OUT2":
                return this.generateDHKeyPair(algorithm);
            default:
                //throw new core.OperationError("algorithm: Is not recognized");
                throw new Error('algorithm: Is not recognized');
        }
    }
    */

    // Method for generating a DHKeyPair - not tested
    /*
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
    */

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