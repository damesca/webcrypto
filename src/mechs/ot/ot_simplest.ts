import * as core from "webcrypto-core";
import { OtCrypto } from "./crypto";
import { Utils } from "./utils";
import { OtProvider, OtParams } from 'webcrypto-core';

//TODO: This interface will be moved
interface OtSimplestDHParams extends OtParams {
    isSender?: boolean,
    privateKey?: string,    //TODO: Change string to CryptoKey when implemented
    publicKey?: string,     //TODO: Change string to CryptoKey when implemented
    prime?: bigint,
    choice?: number;
}

// Not instantiatable class because provider is not declarated into core interface
export class OtSimplest1out2Provider extends core.OtProvider {

    public async onSetup(algorithm: OtSimplestDHParams): Promise<ArrayBuffer[][]> {

        let fixedData: ArrayBuffer[][];

        if(algorithm.isSender === true){
            if(algorithm.privateKey == undefined || algorithm.publicKey == undefined || algorithm.prime == undefined){
                throw new Error('algorithm: sender params are not correct');
            }
            
            /* CryptoKey object has not raw DH algorithm implemented */
            //const publicKey = await crypto.subtle.exportKey('raw', algorithm.publicKey);
            //const privateKey = await crypto.subtle.exportKey('raw', algorithm.privateKey);

            const publicDataSender: ArrayBuffer[] = [Utils.hexStrToBuffer(algorithm.publicKey)];
            const privateDataSender: ArrayBuffer[] = [Utils.hexStrToBuffer(algorithm.privateKey)];

            fixedData = [publicDataSender, privateDataSender];
        }else{
            if(algorithm.privateKey == undefined || algorithm.publicKey == undefined || algorithm.prime == undefined){
                throw new Error('algorithm: receiver params are not correct');
            }

            /* CryptoKey object has not raw DH algorithm implemented */
            //const publicKey = await crypto.subtle.exportKey('raw', algorithm.publicKey);
            //const privateKey = await crypto.subtle.exportKey('raw', algorithm.privateKey);

            const publicDataReceiver: ArrayBuffer[] = [Utils.hexStrToBuffer(algorithm.publicKey)];
            const privateDataReceiver: ArrayBuffer[] = [Utils.hexStrToBuffer(algorithm.privateKey)];

            fixedData = [publicDataReceiver, privateDataReceiver];
        }

        return fixedData;
    }

    public async obliviousPublicKeyDerivation(algorithm: OtSimplestDHParams, publicDataSender: ArrayBuffer[], fixedDataReceiver: ArrayBuffer[][]): Promise<ArrayBuffer[]> {
        
        if(algorithm.prime == undefined){
            throw new Error('algorithm: prime modulus is undefined');
        }
        if(algorithm.choice == undefined){
            throw new Error('algorithm: choice not found');
        }

        // publicDataSender: [ publicKeySender ]
        const publicKeySender = Utils.arrayBufferToBuffer(publicDataSender[0]).toString('hex');

        // fixedDataReceiver: [ [ publicKeyReceiver ], [ privateKeyReceiver ] ]
        const publicKeyReceiver = Utils.arrayBufferToBuffer(fixedDataReceiver[0][0]).toString('hex');
        const privateKeyReceiver = Utils.arrayBufferToBuffer(fixedDataReceiver[1][0]).toString('hex');

        var obliviousPublicKey: string;
        
        if(algorithm.choice === 0){
            
            obliviousPublicKey = publicKeyReceiver;

        }else if(algorithm.choice === 1){

            obliviousPublicKey = await OtCrypto.multiplyDHKeys(publicKeySender, publicKeyReceiver, BigInt(algorithm.prime));
            console.log("\nInside obPubKey: ");
            console.log(obliviousPublicKey);

        }else{
            throw new Error('choice data is wrong');
        }

        const opk = Utils.bufferToArrayBuffer(Utils.hexStrToBuffer(obliviousPublicKey));
        return [opk];
    }

    // Compiling testing content
    public async obliviousEncrypt(algorithm: OtSimplestDHParams, obliviousPublicKey: ArrayBuffer[], fixedDataSender: ArrayBuffer[][], clearMessages: ArrayBuffer[]): Promise<ArrayBuffer[]> {
        
        if(algorithm.prime === undefined){
            throw new Error('algorithm: prime modulus is undefined');
        }

        const publicDataSender = fixedDataSender[0];
        const privateDataSender = fixedDataSender[1];

        const obPublicKey = Utils.arrayBufferToBuffer(obliviousPublicKey[0]).toString('hex');
        const publicKeySender = Utils.arrayBufferToBuffer(publicDataSender[0]).toString('hex');
        const privateKeySender = Utils.arrayBufferToBuffer(privateDataSender[0]).toString('hex');
        const prime = algorithm.prime;

        // B * A^-1
        const pk1 = await OtCrypto.divideDHKeys(obPublicKey, publicKeySender, prime);
        // H((pk1) ^ a)
        const cipherKey0 = await OtCrypto.simmetricKeyDerivation(obPublicKey, privateKeySender, prime);
        const cipherKey1 = await OtCrypto.simmetricKeyDerivation(pk1, privateKeySender, prime);
        
        const clearMessage0 = Utils.arrayBufferToBuffer(clearMessages[0]);
        const clearMessage1 = Utils.arrayBufferToBuffer(clearMessages[1]);

        const cipherMessage0 = await OtCrypto.cipherMessage(cipherKey0, clearMessage0.toString('utf8'));
        const cipherMessage1 = await OtCrypto.cipherMessage(cipherKey1, clearMessage1.toString('utf8'));

        return [
            Utils.bufferToArrayBuffer(Utils.hexStrToBuffer(cipherMessage0)),
            Utils.bufferToArrayBuffer(Utils.hexStrToBuffer(cipherMessage1))
        ];
    }

    // Compiling testing content
    public async obliviousDecrypt(algorithm: Algorithm, publicDataSender: ArrayBuffer[], privateDataReceiver: ArrayBuffer[], encryptedMessages: ArrayBuffer[]): Promise<ArrayBuffer[]> {
        const ab = new Array(new ArrayBuffer(8));
        return ab;
    }

}