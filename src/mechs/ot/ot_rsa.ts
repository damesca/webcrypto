import * as core from "webcrypto-core";
import { OtCrypto } from "./crypto";
import crypto from "crypto";
import { CryptoKey } from "../../keys/key";
import bigInt from "big-integer";

interface OtRsaParamsSender extends core.OtParams {
    privateKey: CryptoKey,
    publicKey: CryptoKey;
}

interface OtRsaParamsReceiver extends core.OtParams {
    choice?: number;
}

export class OtRsaProvider extends core.OtRsaProvider {

    public async onSetup(algorithm: OtRsaParamsSender | OtRsaParamsReceiver): Promise<ArrayBuffer[][]> {
        
        let fixedData: ArrayBuffer[][];

        if(algorithm.isSender == undefined){
            throw new Error('algorithm: isSender not specified');
        }

        // ### SENDER ###
        if(algorithm.isSender == true){
            console.log("\n[###] ONSETUP: IS-SENDER");
            
            const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
                modulusLength: 2048,    // bits
                publicKeyEncoding: {
                    type: 'pkcs1',
                    format: 'pem',
                },
                privateKeyEncoding: {
                    type: 'pkcs1',
                    format: 'pem',
                    cipher: 'aes-256-cbc',
                    passphrase: '',
                },
            });

            const x0 = crypto.randomBytes(128); // bytes
            const x1 = crypto.randomBytes(128);
            console.log("X0: " + x0.toString('hex'));
            console.log("X1: " + x1.toString('hex'));

            // fixedData = [ [ publicData ], [ privateData ] ]
            fixedData = [ [ new Buffer(publicKey), x0, x1 ], [ new Buffer(privateKey) ] ];

        // ### RECEIVER ###
        }else if(algorithm.isSender == false){

            console.log("\n[###] ONSETUP: IS-RECEIVER");

            const k = crypto.randomBytes(128);
            console.log("K: " + k.toString('hex'));

            // fixedData = [ [ publicData ], [ privateData ] ]
            fixedData = [ [], [ k ] ];

        }else{
            throw new Error('algorithm: type is not recognized');
        }

        return fixedData;
    }

    public async onObliviousPublicKeyDerivation(algorithm: OtRsaParamsReceiver, publicDataSender: ArrayBuffer[], fixedDataReceiver: ArrayBuffer[][]): Promise<ArrayBuffer[]> {
        
        console.log("\n[###] ONOBLIVIOUSPUBLICKEYDERIVATION");
        if(algorithm.choice === undefined){
            throw new Error('algorithm: choice member is not defined');
        }

        const pemPublicKey = publicDataSender[0];
        const x0 = publicDataSender[1];
        const x1 = publicDataSender[2];
        const k = fixedDataReceiver[1][0];

        const publicKey = crypto.createPublicKey(new Buffer(pemPublicKey));
        
        var v;

        if(algorithm.choice == 0){
            
            v = OtCrypto.os2ip(new Buffer(x0)).add(OtCrypto.os2ip(new Buffer(k)));
            console.log("\nV(0): " + v.toString());    

        }else if(algorithm.choice == 1){

            v = OtCrypto.os2ip(new Buffer(x1)).add(OtCrypto.os2ip(new Buffer(k)));
            console.log("\nV(1): " + v.toString())

        }else{
            throw new Error('algorithm: choice value is not valid');
        }

        const length = Math.ceil(v.bitLength().valueOf() / 8);
        console.log("\nLength: " + length);
        const os_v = OtCrypto.i2osp(v, Math.ceil(v.bitLength().valueOf() / 8));
        console.log("\nOS_V: " + os_v.toString('hex'));
        const cipher_v = crypto.publicEncrypt(publicKey, os_v);
        
        return [cipher_v];
    }

    public async onObliviousEncrypt(algorithm: OtRsaParamsSender, obliviousPublicKey: ArrayBuffer[], fixedDataSender: ArrayBuffer[][], clearMessages: ArrayBuffer[]): Promise<ArrayBuffer[][]> {
        console.log("\n[###] ONOBLIVIOUSENCRYPT");
        const pemPrivateKey = fixedDataSender[1][0];
        const privateKey = crypto.createPrivateKey({ key: new Buffer(pemPrivateKey), passphrase: '' });
        const cipher_v = new Buffer(obliviousPublicKey[0]);
        const v = crypto.privateDecrypt(privateKey, cipher_v);
        console.log("\nV: " + v.toString('hex'));
        const num_x0 = OtCrypto.os2ip(new Buffer(fixedDataSender[0][1]));
        const num_x1 = OtCrypto.os2ip(new Buffer(fixedDataSender[0][2]));
        const num_v = OtCrypto.os2ip(v);
        var n_k0 = num_v.minus(num_x0);
        var n_k1 = num_v.minus(num_x1);
        console.log("\nSize_k0: " + n_k0.bitLength().valueOf());
        console.log("\nSize_k1: " + n_k1.bitLength().valueOf());
        const k0 = OtCrypto.i2osp(n_k0, Math.ceil(n_k0.bitLength().valueOf() / 8));
        const k1 = OtCrypto.i2osp(n_k1, Math.ceil(n_k1.bitLength().valueOf() / 8));
        console.log("\nK0: " + k0.toString('hex'));
        console.log("\nK1: " + k1.toString('hex'));
        var hash = crypto.createHash('sha256');
        const sec_k0 = crypto.createSecretKey(hash.update(k0).digest());
        hash = crypto.createHash('sha256');
        const sec_k1 = crypto.createSecretKey(hash.update(k1).digest());
        console.log("\nSec_k0: " + sec_k0.export().toString('hex'));
        console.log("\nSec_k1: " + sec_k1.export().toString('hex'));
        const m0 = clearMessages[0];
        const m1 = clearMessages[1];
        const iv = Buffer.alloc(16, 0);
        var cipher = crypto.createCipheriv('aes-256-cbc', sec_k0, iv);
        var cipher_m0 = cipher.update(new Buffer(m0));
        cipher_m0 = Buffer.concat([cipher_m0, cipher.final()]);
        cipher = crypto.createCipheriv('aes-256-cbc', sec_k1, iv);
        var cipher_m1 = cipher.update(new Buffer(m1));
        cipher_m1 = Buffer.concat([cipher_m1, cipher.final()]);
        console.log("\nCipher_m0: " + cipher_m0.toString('hex'));
        console.log("\nCipher_m1: " + cipher_m1.toString('hex'));

        return [[cipher_m0], [cipher_m1]];
    }
    
    public async onObliviousDecrypt(algorithm: OtRsaParamsReceiver, publicDataSender: ArrayBuffer[], fixedDataReceiver: ArrayBuffer[][], encryptedMessages: ArrayBuffer[][]): Promise<ArrayBuffer[]> {
        console.log("\n[###] ONOBLIVIOUSDECRYPT");

        if(algorithm.choice === undefined){
            throw new Error('algorithm: choice member is not defined');
        }
        
        const k = new Buffer(fixedDataReceiver[1][0]);
        var hash = crypto.createHash('sha256');
        var f_hash = hash.update(k).digest();
        const sec_k = crypto.createSecretKey(f_hash);
        console.log("\nSec_k: " + sec_k.export().toString('hex'));

        var cipher_m;
        if(algorithm.choice == 0){
            cipher_m = new Buffer(encryptedMessages[0][0]);
        }else if(algorithm.choice == 1){
            cipher_m = new Buffer(encryptedMessages[1][0]);
        }else{
            throw new Error('algorithm: choice value is not valid');
        }
        console.log("\nCipher_Message: " + cipher_m.toString('hex'));

        const iv = Buffer.alloc(16, 0);
        var decipher = crypto.createDecipheriv('aes-256-cbc', f_hash, iv);
        var message = decipher.update(cipher_m);
        message = Buffer.concat([message, decipher.final()]);
        console.log("\nMessage: " + message.toString('hex'));

        return [ message ];
    }

    // Type Checker
    private isOtRsaParamsSender(algorithm: OtRsaParamsSender | OtRsaParamsReceiver): algorithm is OtRsaParamsSender {
        return 'member' in algorithm;
    }

    private isOtRsaParamsReceiver(algorithm: OtRsaParamsSender | OtRsaParamsReceiver): algorithm is OtRsaParamsReceiver {
        return 'member' in algorithm;
    }

}