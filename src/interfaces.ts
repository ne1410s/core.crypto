export interface IKeyPair_Jwk {
    publicJwk: JsonWebKey
    privateJwk: JsonWebKey
}

export interface ICsr_Params {
    domain: string
    country: string
    town: string
    county: string
    company: string
    department: string
}

export interface ICsr_Result extends IKeyPair_Jwk {
    der: string
    pem: string
    pkcs8: string
}