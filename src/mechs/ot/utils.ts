
import bigInt from 'big-integer';

/* Helper class for data conversions */
export class Utils{

    // From hexString to Buffer
    public static hexStrToBuffer(hexStr: string){
        var str = hexStr;
        var res = [];
        while(str.length >= 2){
            res.push(parseInt(str.substring(0, 2), 16));
            str = str.substring(2, str.length);
        }
        var buf = Buffer.alloc(res.length);
        for(var i = 0; i < res.length; i++){
            buf[i] = res[i];
        }
        return buf;
    }

    // From Buffer to ArrayBuffer
    public static bufferToArrayBuffer(buf: Buffer){
        var ab = new ArrayBuffer(buf.length);
        var view = new Uint8Array(ab);
        for(var i = 0; i < buf.length; i++){
            view[i] = buf[i];
        }
        return ab;
    }

    // From ArrayBuffer to Buffer
    public static arrayBufferToBuffer(ab: ArrayBuffer){
        var view = new Uint8Array(ab);
        return Buffer.from(ab);
    }

    // Compute x^a mod p
    public static modPow(base: BigInt, exp: BigInt, mod: BigInt){
        var x = bigInt(bigInt(base.toString(16), 16));
        var a = bigInt(bigInt(exp.toString(16), 16));
        var p = bigInt(bigInt(mod.toString(16), 16));
        var r = bigInt(0); // Not initialized
        var y = bigInt(1);
        while(a.compare(0) == 1){ // Returns 1 if a > 0
            r = a.mod(2);
            // Fast exponentiation
            if(r.compare(1) == 0){   // Returns 0 if r == 0
                y = (y.multiply(x).mod(p));
            }
            x = x.multiply(x).mod(p);
            a = a.divide(2);
        }
        return y;
    }

    // Modular inverse 
    public static modInverse(number: BigInt, mod: BigInt){
        const p = bigInt(mod.toString(16), 16);
        return bigInt(number.toString(16), 16).modInv(p);
    }
}