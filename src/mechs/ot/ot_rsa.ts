import * as core from "webcrypto-core";
import {OtCrypto} from "./crypto";
import crypto from "crypto";
import base64url from "base64url";
var JSONWebKey = require('json-web-key');

// Specific protocol interface for adding params
interface OtRsaParams extends core.OtParams{ }

export class OtRsaProvider extends core.OtRsaProvider {

    public async onSetup(algorithm: OtRsaParams): Promise<ArrayBuffer[][]> {
        
        let fixedData: ArrayBuffer[][];

        // Params checking
        if(algorithm.isSender == undefined){
            throw new Error('algorithm: isSender not specified');
        }

        // ### SENDER ###
        if(algorithm.isSender == true){
            
            const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
                modulusLength: 2048,
                publicKeyEncoding: {
                    type: 'pkcs1',
                    format: 'pem',
                },
                privateKeyEncoding: {
                    type: 'pkcs1',
                    format: 'pem',
                },
            });

            const x0 = crypto.randomBytes(128);
            const x1 = crypto.randomBytes(128);
            fixedData = [ [ new Buffer(publicKey), x0, x1 ], [ new Buffer(privateKey) ] ];
            // fixedData = [ [ publicData ], [ privateData ] ]

            console.log("\n### [ON SETUP: IS SENDER] ###\n");
            console.log("X0: " + x0.toString('hex'));
            console.log("X1: " + x1.toString('hex'));

        // ### RECEIVER ###
        }else if(algorithm.isSender == false){

            // Generate random K, comparing it with upper bound modulus N
            const jsonWebPublicKey = JSONWebKey.fromPEM(new Buffer(algorithm.rawPublicKey as ArrayBuffer)).toJSON();
            const n = base64url.decode(jsonWebPublicKey['n'], "hex");
            const e = base64url.decode(jsonWebPublicKey['e'], "hex");
            var k = crypto.randomBytes(256);
            while(OtCrypto.os2ip(new Buffer(n, 'hex')).compare(OtCrypto.os2ip(k)) == -1){
                k = crypto.randomBytes(256);
                console.log("\nK (rep): " + k.toString('hex'));
            }

            fixedData = [ [], [ k ] ];
            // fixedData = [ [ publicData ], [ privateData ] ]

            console.log("\n### [ON SETUP: IS RECEIVER] ###\n");
            console.log("\nPublicKey: " + new Buffer(algorithm.rawPublicKey as ArrayBuffer).toString());
            console.log("\nK: " + k.toString('hex'));

        }else{
            throw new Error('algorithm: type is not recognized');
        }

        return fixedData;
    }

    public async onObliviousPublicKeyDerivation(algorithm: OtRsaParams, publicDataSender: ArrayBuffer[], fixedDataReceiver: ArrayBuffer[][]): Promise<ArrayBuffer[]> {
        
        console.log("\n### [ON OBLIVIOUS PUBLIC KEY DERIVATION] ###");
        if(algorithm.choice === undefined){
            throw new Error('algorithm: choice member is not defined');
        }

        // Extract protocol params
        const pemPublicKey = publicDataSender[0];
        const x0 = publicDataSender[1];
        const x1 = publicDataSender[2];
        const k = fixedDataReceiver[1][0];

        // Convert pemPublicKey to JSONWebKey and extract params
        const webKey = JSONWebKey.fromPEM(new Buffer(pemPublicKey));
        const json_key = webKey.toJSON();
        console.log("# JSONWebKey[Public] #");
        console.log(json_key);

        const n = base64url.decode(json_key['n'], "hex");
        const e = base64url.decode(json_key['e'], "hex");
        console.log("n y e");

        // RawEncrypt secret K
        const encrypted_k = OtCrypto.rawRsaEncrypt(new Buffer(n, "hex"), new Buffer(e, "hex"), new Buffer(k));
        console.log("\nEncrypted_K: " + encrypted_k.toString('hex'));
        console.log("\nLength: " + encrypted_k.length);
        console.log("\nX0: " + new Buffer(x0).toString('hex'));
        console.log("\nX1: " + new Buffer(x1).toString('hex'));
        console.log("\nK: " + new Buffer(k).toString('hex'));

        // Add choice Xc to encrypted K to build ObKey
        const int_k = OtCrypto.os2ip(encrypted_k);
        var v;

        if(algorithm.choice === 0){
            
            v = OtCrypto.os2ip(new Buffer(x0)).add(int_k);
            console.log("\nV(0): " + v.toString());    

        }else if(algorithm.choice === 1){

            v = OtCrypto.os2ip(new Buffer(x1)).add(int_k);
            console.log("\nV(1): " + v.toString())

        }else{
            throw new Error('algorithm: choice value is not correct');
        }

        const os_v = OtCrypto.i2osp(v, Math.ceil(v.bitLength().valueOf() / 8));
        console.log("\nV: " + os_v.toString('hex'));

        return [ os_v ];

    }

    public async onObliviousEncrypt(algorithm: OtRsaParams, obliviousPublicKey: ArrayBuffer[], fixedDataSender: ArrayBuffer[][], clearMessages: ArrayBuffer[]): Promise<ArrayBuffer[][]> {

        console.log("\n##########\nON OBLIVIOUS ENCRYPT\n##########");

        // Get params
        const pemPrivateKey = fixedDataSender[1][0];
        const v = obliviousPublicKey[0];
        const x0 = fixedDataSender[0][1];
        const x1 = fixedDataSender[0][2];

        // Convert pemPrivateKey to JSONWebKey and extract params
        const json_key = JSONWebKey.fromPEM(new Buffer(pemPrivateKey));
        console.log("# JSONWebKey[Private] #");
        console.log(json_key);
        const n = json_key['n'];
        const d = json_key['d'];

        // (v - x0) & (v - x1) to obtain tmp_k0 & tmp_k1 
        const num_v = OtCrypto.os2ip(new Buffer(v));
        const num_x0 = OtCrypto.os2ip(new Buffer(x0));
        const num_x1 = OtCrypto.os2ip(new Buffer(x1));

        const tmp_k0 = num_v.minus(num_x0);
        const tmp_k1 = num_v.minus(num_x1);
        
        
        console.log("\n[Pre-Decrypted]Supp_K0");
        console.log(OtCrypto.i2osp(tmp_k0, Math.ceil(tmp_k0.bitLength().valueOf() / 8)).toString('hex'));
        console.log("\n[Pre-Decrypted]Supp_K1");
        console.log(OtCrypto.i2osp(tmp_k1, Math.ceil(tmp_k1.bitLength().valueOf() / 8)).toString('hex'));

        console.log("\n[Number]Supp_K0");
        console.log(tmp_k0.toString())
        console.log("\n[Number]Supp_K1");
        console.log(tmp_k1.toString())

        // Decrypt k0 & k1
        const supp_k0 = OtCrypto.rawRsaDecrypt(n, d, OtCrypto.i2osp(tmp_k0, Math.ceil(tmp_k0.bitLength().valueOf() / 8)));
        const supp_k1 = OtCrypto.rawRsaDecrypt(n, d, OtCrypto.i2osp(tmp_k1, Math.ceil(tmp_k1.bitLength().valueOf() / 8)));
        console.log("\nSUPP_K0: " + supp_k0.toString('hex'));
        console.log("\nSUPP_K1: " + supp_k1.toString('hex'));

        // Hash k0 & k1 to obtain fixed keys
        var hash = crypto.createHash('sha256');
        var f_hash = hash.update(supp_k0).digest();
        const fixed_k0 = crypto.createSecretKey(f_hash);
        var hash = crypto.createHash('sha256');
        var f_hash = hash.update(supp_k1).digest();
        const fixed_k1 = crypto.createSecretKey(f_hash);
        console.log("\nFixed_k0: " + fixed_k0.export().toString('hex'));
        console.log("\nFixed_k1: " + fixed_k1.export().toString('hex'));

        // Encrypt messages using keys
        const iv = Buffer.alloc(16, 0);
        var cipher = crypto.createCipheriv('aes-256-cbc', fixed_k0, iv);
        var encrypted_m0 = cipher.update(new Buffer(clearMessages[0]));
        encrypted_m0 = Buffer.concat([encrypted_m0, cipher.final()]);
        cipher = crypto.createCipheriv('aes-256-cbc', fixed_k1, iv);
        var encrypted_m1 = cipher.update(new Buffer(clearMessages[1]));
        encrypted_m1 = Buffer.concat([encrypted_m1, cipher.final()]);
        console.log("\nEncrypted_m0: " + encrypted_m0.toString('hex'));
        console.log("\nEncrypted_m1: " + encrypted_m1.toString('hex'));

        return [[encrypted_m0], [encrypted_m1]];
    }
    
    public async onObliviousDecrypt(algorithm: OtRsaParams, publicDataSender: ArrayBuffer[], fixedDataReceiver: ArrayBuffer[][], encryptedMessages: ArrayBuffer[][]): Promise<ArrayBuffer[]> {
        console.log("\n##########\nON OBLIVIOUS DECRYPT\n##########");

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

}