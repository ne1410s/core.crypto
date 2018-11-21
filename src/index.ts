import Text from "@ne1410s/text";
import { IKeyPair_JWK } from './interfaces';

const DEF_ALGO: RsaHashedKeyGenParams = {
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: { name: 'SHA-256' },
};

export default abstract class Crypto {
    
    public static async gen(): Promise<IKeyPair_JWK> {

        const keys = await crypto.subtle.generateKey(DEF_ALGO, true, ['sign']);
        return {
            private: await crypto.subtle.exportKey('jwk', keys.privateKey),
            public: await crypto.subtle.exportKey('jwk', keys.publicKey)
        };
    }
}