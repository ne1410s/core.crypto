import Text from "@ne1410s/text";
import * as WebCrypto from "node-webcrypto-ossl";

const crypto = new WebCrypto();
const DEF_ALGO: RsaHashedKeyGenParams = {
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: { name: 'SHA-256' },
};

export default abstract class Crypto {
    
    public static async gen(text: string): Promise<any> {

        const keys = await crypto.subtle.generateKey(DEF_ALGO, true, ['sign']);
        return {
            publicJwk: await crypto.subtle.exportKey('jwk', keys.publicKey),
            privateJwk: await crypto.subtle.exportKey('jwk', keys.privateKey)
        };
    }
}