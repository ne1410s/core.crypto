import Text from "@ne1410s/text";
import { JWKPair } from './interfaces';

export abstract class Crypto {
    
    public static async gen(): Promise<JWKPair> {
        const keys = await crypto.subtle.generateKey('', true, ['sign']);
        return new JWKPair();
    }

}