import * as WebCrypto from "node-webcrypto-ossl";
import * as asn1js from "asn1js";
import { Text } from "@ne1410s/text";
import { IKeyPair_Jwk, ICsr_Params, ICsr_Result } from "./interfaces";

var pkijs = require('pkijs');

const webcrypto = new WebCrypto();
pkijs.setEngine("newEngine", webcrypto, new pkijs.CryptoEngine({ name: "", crypto: webcrypto, subtle: webcrypto.subtle }));

const DEF_ALGO: RsaHashedKeyGenParams = {
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: { name: 'SHA-256' },
};

export abstract class Crypto {

    public static async randomString(): Promise<string> {
        
        const bytes = new Uint8Array(24);
        webcrypto.getRandomValues(bytes);

        return Text.bufferToBase64Url(bytes.buffer);

    }

    public static async gen(): Promise<IKeyPair_Jwk> {

        const keys = await webcrypto.subtle.generateKey(DEF_ALGO, true, ['sign']);
        return {
            publicJwk: await webcrypto.subtle.exportKey('jwk', keys.publicKey),
            privateJwk: await webcrypto.subtle.exportKey('jwk', keys.privateKey)
        };
    }

    public static async sign(text: string, privateJwk: JsonWebKey): Promise<string> {

        const cKey = await webcrypto.subtle.importKey('jwk', privateJwk, DEF_ALGO, true, ['sign']),
              buffer = Text.textToBuffer(text),
              signed = await webcrypto.subtle.sign(DEF_ALGO.name, cKey, buffer);

        return Text.bufferToBase64Url(signed);
    }

    public static async digest(text: string): Promise<string> {

        const buffer = Text.textToBuffer(text),
              digest = await webcrypto.subtle.digest('SHA-256', buffer);

        return Text.bufferToBase64Url(digest);
    }

    public static async csr(params: ICsr_Params): Promise<ICsr_Result> {

        const pkcs10 = new pkijs.CertificationRequest();
        pkcs10.version = 0;

        (params.domains || []).forEach(domain => {
            pkcs10.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
                type: '2.5.4.3',
                value: new asn1js.Utf8String({ value: domain })
            }));
        });

        if (params.country) {
            pkcs10.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
                type: '2.5.4.6',
                value: new asn1js.PrintableString({ value: params.country })
            }));
        }

        if (params.town) {
            pkcs10.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
              type: "2.5.4.7",
              value: new asn1js.Utf8String({ value: params.town })
            }));
        }

        if (params.county) {
            pkcs10.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
              type: "2.5.4.8",
              value: new asn1js.Utf8String({ value: params.county })
            }));
        }
 
        if (params.department) {
            pkcs10.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
                type: "2.5.4.10",
                value: new asn1js.Utf8String({ value: params.department })
            }));
        }

        if (params.company) {
            pkcs10.subject.typesAndValues.push(new pkijs.AttributeTypeAndValue({
                type: "2.5.4.11",
                value: new asn1js.Utf8String({ value: params.company })
            }));
        }

        const keys = await webcrypto.subtle.generateKey(DEF_ALGO, true, ['sign']);
        const publicKey = keys.publicKey as CryptoKey;

        await pkcs10.subjectPublicKeyInfo.importKey(publicKey);

        var toDigest = pkcs10.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex;
        var pubkeyhash_sha1 = await webcrypto.subtle.digest('SHA-1', toDigest);
        //pubkeyhash_sha256 = await webcrypto.subtle.digest('SHA-256', toDigest);
        
        pkcs10.attributes = [];
        pkcs10.attributes.push(new pkijs.Attribute({
            type: "1.2.840.113549.1.9.14", // pkcs-9-at-extensionRequest
            values: [(new pkijs.Extensions({
            extensions_array: [
                new pkijs.Extension({
                    extnID: "2.5.29.14",
                    critical: false,
                    extnValue: (new asn1js.OctetString({
                        valueHex: pubkeyhash_sha1
                    })).toBER(false)
                })
            ]
            })).toSchema()]
        }));
        
        const privateKey = keys.privateKey as CryptoKey,
              signedPKCS10 = await pkcs10.sign(privateKey, 'SHA-256'),
              pkcs10_schema = pkcs10.toSchema(),
              pkcs10_encoded = pkcs10_schema.toBER(false),
              exportedPkcs8 = await webcrypto.subtle.exportKey('pkcs8', keys.privateKey);

        return { 
            pem: Crypto.toPem(pkcs10_encoded, 'CERTIFICATE REQUEST'),
            der: Text.bufferToBase64Url(pkcs10_encoded),
            pkcs8: Crypto.toPem(exportedPkcs8, 'PRIVATE KEY'),
            privateJwk: await webcrypto.subtle.exportKey('jwk', keys.privateKey),
            publicJwk: await webcrypto.subtle.exportKey('jwk', keys.publicKey)
        };
    }
    
    //https://github.com/PeculiarVentures/PKI.js/blob/master/examples/PKCS12SimpleExample/es6.js
    public static async pfx(cert_b64: string, key_b64: string, password: string, hash: string = 'SHA-256'): Promise<ArrayBuffer> {

        const asn1_cer = asn1js.fromBER(Text.textToBuffer(Text.base64ToText(cert_b64))),
              asn1_key = asn1js.fromBER(Text.textToBuffer(Text.base64ToText(key_b64)));

        const objc_cer = new pkijs.Certificate({ schema: asn1_cer.result }),
              objc_key = new pkijs.PrivateKeyInfo({ schema: asn1_key.result });

        const pkcs12 = new pkijs.PFX({
            parsedValue: {
                integrityMode: 0, // Password-Based Integrity Mode
                authenticatedSafe: new pkijs.AuthenticatedSafe({
                    parsedValue: {
                        safeContents: [
                            {
                                privacyMode: 0, // "No Privacy" mode
                                value: new pkijs.SafeContents({
                                    safeBags: [
                                        new pkijs.SafeBag({
                                            bagId: "1.2.840.113549.1.12.10.1.1",
                                            bagValue: objc_key
                                        }),
                                        new pkijs.SafeBag({
                                            bagId: "1.2.840.113549.1.12.10.1.3",
                                            bagValue: new pkijs.CertBag({
                                                parsedValue: objc_cer
                                            })
                                        })
                                    ]
                                })
                            }
                        ]
                    }
                })
            }
        });

        await pkcs12.parsedValue.authenticatedSafe.makeInternalValues({
			safeContents: [{ /* Empty as "No Privacy" for SafeContents */ }]
        });
        
        await pkcs12.makeInternalValues({
            password: Text.textToBuffer(password),
			iterations: 100000,
			pbkdf2HashAlgorithm: hash,
			hmacHashAlgorithm: hash
        });

        return pkcs12.toSchema().toBER(false);
    }

    private static toPem(pkcs10_buf: ArrayBuffer, title: string): string {

        const pem_string = btoa(Text.bufferToText(pkcs10_buf)),
              string_length = pem_string.length;

        let result_string = '';
        for (var i = 0, count = 0; i < string_length; i++, count++) {
            if (count > 63) { result_string += "\r\n"; count = 0; }
            result_string += pem_string[i];
        }

        return `-----BEGIN ${title}-----\r\n${result_string}\r\n-----END ${title}-----\r\n`;
    }
}