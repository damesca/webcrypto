import * as core from "webcrypto-core";
import { OtCrypto } from "./crypto";
import { Utils } from "./utils";
import { Crypto } from "../../crypto";

interface OtRsaParams extends Algorithm {
    m?: number,
    n?: number,
    isSender?: boolean,
    privateKey?: CryptoKey[],
    publicKey?: CryptoKey[],
    choice?: number[];
}

// TODO: Implement (OtProvider or OtRsaProvider ???) into core with abstract methods for OtProvider
export class OtRsaProvider extends core.OtRsaProvider {

    readonly name = "OT-RSA";
    crypto = new Crypto();

    public async onSetup(algorithm: OtRsaParams): Promise<ArrayBuffer[][]> {

        let fixedData: ArrayBuffer[][];

        if(algorithm.isSender == undefined){
            throw new Error('algorithm: isSender not specified');
        }

        if(algorithm.isSender === true){

            if(algorithm.publicKey == undefined || algorithm.privateKey == undefined){
                throw new Error('algorithm: sender params are not correct');
            }
            
            const publicKeyList = algorithm.publicKey as CryptoKey[];
            const privateKeyList = algorithm.privateKey as CryptoKey[];

            // Encapsulate RsaPublicKey[] into publicDataSender
            var rawPublicKeyList: ArrayBuffer[] = new Array(publicKeyList.length);
            for(var i = 0; i < publicKeyList.length; i++){
                rawPublicKeyList[i] = await this.crypto.subtle.exportKey('raw', publicKeyList[i]);
            }

            // Encapsulate RsaPrivateKey[] into privateDataSender
            var rawPrivateKeyList: ArrayBuffer[] = new Array(privateKeyList.length);
            for(var i = 0; i < privateKeyList.length; i++){
                rawPrivateKeyList[i] = await this.crypto.subtle.exportKey('raw', privateKeyList[i]);
            }

            const publicDataSender: ArrayBuffer[] = rawPublicKeyList;
            const privateDataSender: ArrayBuffer[] = rawPrivateKeyList;
            fixedData = [ publicDataSender, privateDataSender ];

        }else{

            if(algorithm.privateKey == undefined){
                throw new Error('algorithm: receiver params are not correct');
            }

            const secretKeyList = algorithm.privateKey as CryptoKey[];

            // Encapsulate simmetricKey[] into privateDataReceiver
            var rawSecretKeyList: ArrayBuffer[] = new Array(secretKeyList.length);
            for(var i = 0; i < secretKeyList.length; i++){
                rawSecretKeyList[i] = await this.crypto.subtle.exportKey('raw', secretKeyList[i]);
            }

            const publicDataReceiver: ArrayBuffer[] = [];
            const privateDataReceiver: ArrayBuffer[] = rawSecretKeyList;
            fixedData = [ publicDataReceiver, privateDataReceiver ];

        }

        return fixedData;
    }

}