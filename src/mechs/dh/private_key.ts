// IMPORTS
import { AsymmetricKey } from "../../keys";

export class DhPrivateKey extends AsymmetricKey {
    public readonly type: "private" = "private";
    public algortihm!: DhKeyAlgorithm;
    //TODO: Add methods
}