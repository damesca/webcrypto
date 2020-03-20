// IMPORTS
import { CryptoKey } from "../../keys";
import { DhPrivateKey } from "./private_key";
import { DhPublicKey } from './public_key';
import crypto from "crypto";

export class DhCrypto {

    public static publicKeyUsages = ["verify", "encrypt", "wrapKey"];
    public static privateKeyUsages = ["sign", "decrypt", "unwrapKey"];

    public static async generateKey(algorithm: DhKeyGenParams, extractable: boolean, keyUsages: KeyUsage[]): Promise<CryptoKeyPair> {
        const privateKey = new DhPrivateKey();
        privateKey.algorithm = algorithm;
        privateKey.extractable = extractable;
        privateKey.usages = keyUsages.filter((usage) => this.privateKeyUsages.indexOf(usage) !== -1);
    
        const publicKey = new DhPublicKey();
        publicKey.algorithm = algorithm;
        publicKey.extractable = true;
        publicKey.usages = keyUsages.filter((usage) => this.publicKeyUsages.indexOf(usage) !== -1);
    
        const hexPrime = Buffer.from(algorithm.prime).toString('hex');
        const dh = crypto.createDiffieHellman(hexPrime, 'hex', algorithm.generator);
        publicKey.data = dh.generateKeys();
        privateKey.data = dh.getPrivateKey();

        const res: CryptoKeyPair = {
            privateKey,
            publicKey,
        };

        return res;
    }

}