import * as core from "webcrypto-core";
import { OtCrypto } from "./crypto";
import { Utils } from "./utils";
import { Crypto } from "../../crypto";
import { OtParams } from 'webcrypto-core';

interface OtRsaParamsSender extends OtParams {
    m?: number,
    n?: number,
    privateKey: CryptoKey[],
    publicKey: CryptoKey[];
}

interface OtRsaParamsReceiver extends OtParams {
    m?: number,
    n?: number,
    privateKey: CryptoKey[],    // TODO: Change private to simmetric, here and into core definition
    choice?: number[];
}

// TODO: Implement (OtProvider or OtRsaProvider ???) into core with abstract methods for OtProvider
export class OtRsaProvider extends core.OtRsaProvider {

    crypto = new Crypto();

    // TODO: (??) Integrate m and n params into publicData Array

    public async onSetup(algorithm: OtRsaParamsSender | OtRsaParamsReceiver): Promise<ArrayBuffer[][]> {

        let fixedData: ArrayBuffer[][];

        if(algorithm.isSender == undefined){
            throw new Error('algorithm: isSender not specified');
        }

        // ### SENDER ###
        if(this.isOtRsaParamsSender(algorithm)){

            if(algorithm.publicKey == undefined || algorithm.privateKey == undefined){
                throw new Error('algorithm: sender params are not correct');
            }
            
            const publicKeyList = algorithm.publicKey as CryptoKey[];   // TOCHECK
            const privateKeyList = algorithm.privateKey as CryptoKey[]; // TOCHECK

            // Encapsulate RsaPublicKey[] into publicDataSender
            var rawPublicKeyList: ArrayBuffer[] = new Array(publicKeyList.length);
            for(var i = 0; i < publicKeyList.length; i++){
                rawPublicKeyList[i] = await this.crypto.subtle.exportKey('pkcs8', publicKeyList[i]);
            }

            // Encapsulate RsaPrivateKey[] into privateDataSender
            var rawPrivateKeyList: ArrayBuffer[] = new Array(privateKeyList.length);
            for(var i = 0; i < privateKeyList.length; i++){
                rawPrivateKeyList[i] = await this.crypto.subtle.exportKey('pkcs8', privateKeyList[i]);
            }

            const publicDataSender: ArrayBuffer[] = rawPublicKeyList;
            const privateDataSender: ArrayBuffer[] = rawPrivateKeyList;
            fixedData = [ publicDataSender, privateDataSender ];

        // ### RECEIVER ###
        }else if(this.isOtRsaParamsReceiver(algorithm)){

            if(algorithm.privateKey == undefined){
                throw new Error('algorithm: receiver params are not correct');
            }

            const secretKeyList = algorithm.privateKey as CryptoKey[];

            // Encapsulate simmetricKey[] into privateDataReceiver
            var rawSecretKeyList: ArrayBuffer[] = new Array(secretKeyList.length);
            for(var i = 0; i < secretKeyList.length; i++){
                rawSecretKeyList[i] = await this.crypto.subtle.exportKey('pkcs8', secretKeyList[i]);
            }

            const publicDataReceiver: ArrayBuffer[] = [];
            const privateDataReceiver: ArrayBuffer[] = rawSecretKeyList;
            fixedData = [ publicDataReceiver, privateDataReceiver ];

        }else{
            throw new Error('algorithm: type is not recognized');
        }

        return fixedData;
    }

    public async onObliviousPublicKeyDerivation(algorithm: OtRsaParamsReceiver, publicDataSender: ArrayBuffer[], fixedDataReceiver: ArrayBuffer[][]): Promise<ArrayBuffer[]> {
        
        if(algorithm.choice === undefined){
            throw new Error('algorithm: choice member is not defined');
        }

        const simmetricFormatedKeyList = fixedDataReceiver[1];  //ArrayBuffer which contains simmetric keys from receiver
        // NOT NECESARY TO IMPORT SIMMETRIC KEY ???
        
        var simmetricKeyList: Array<CryptoKey> = new Array(simmetricFormatedKeyList.length);

        // TODO: Generalize AlgorithmIdentifier
        for(var i = 0; i < simmetricFormatedKeyList.length; i++){
            simmetricKeyList[i] = await this.crypto.subtle.importKey('pkcs8', simmetricFormatedKeyList[i],"AES-CBC", true, ['encrypt', 'wrapKey', 'unwrapKey']);
        }

        const publicFormatedKeyList = publicDataSender;
        var publicKeyList: Array<CryptoKey> = new Array(publicFormatedKeyList.length);

        // TODO: Generalize AlgorithmIdentifier
        for(var i = 0; i < publicFormatedKeyList.length; i++){
            publicKeyList[i] = await this.crypto.subtle.importKey('pkcs8', publicFormatedKeyList[i], "RSA-OAEP", true, ['encrypt']);
        }

        var encryptedKeys: Array<ArrayBuffer> = new Array(simmetricKeyList.length);
        var j = 0;
        for(var i = 0; i < algorithm.choice.length; i++){
            if(algorithm.choice[i] == 1){
                encryptedKeys[j] = await this.crypto.subtle.wrapKey('pkcs8', simmetricKeyList[j], publicKeyList[i], { name: 'AES-CBC' });
                j++;
            }
        }

        return encryptedKeys;
    }

    public async onObliviousEncrypt(algorithm: OtRsaParamsSender, obliviousPublicKey: ArrayBuffer[], fixedDataSender: ArrayBuffer[][], clearMessages: ArrayBuffer[]): Promise<ArrayBuffer[]> {
        const a = new ArrayBuffer(8);
        return [a];
    }
    
    public async onObliviousDecrypt(algorithm: OtRsaParamsReceiver, publicDataSender: ArrayBuffer[], privateDataReceiver: ArrayBuffer[], encryptedMessages: ArrayBuffer[]): Promise<ArrayBuffer[]> {
        const a = new ArrayBuffer(8);
        return [a];
    }

    // Type Checker
    private isOtRsaParamsSender(algorithm: OtRsaParamsSender | OtRsaParamsReceiver): algorithm is OtRsaParamsSender {
        return 'member' in algorithm;
    }

    private isOtRsaParamsReceiver(algorithm: OtRsaParamsSender | OtRsaParamsReceiver): algorithm is OtRsaParamsReceiver {
        return 'member' in algorithm;
    }

}