// IMPORTS

import { AsymmetricKey } from '../../keys';


export class DhPublicKey extends AsymmetricKey {
    public readonly type: "public" = "public";
    public algorithm!: DhKeyAlgorithm;
    // TODO: Add methods
}