const expect = require('chai').expect;
const ne14 = {
    crypto: require('../dist/index').default
};

const TEST_KEY = { 
    kty: 'RSA', 
    key_ops: [ 'sign' ],
    e: 'AQAB',
    n: 'tooelJyzvanRGeEwfRGzemT11cGuhVlfzP-CeCoVrthpLbOAjPHxTxyg1mNTox0HvLwh_CGl9t7z0xL-1Vm-EzAdpGe8MyZWW2X6_yJeQx17qq8bUCfOmJF_BxzXO_OJOH9yglX-wpyQNo_TKJxUVt4qch_j3mOVMmW5WBeHAj1dlS3Rl1Imlm6BrqAlM88WAmJ6k_wzWN0yqLHcdv8dihs3uIgU0lGR2Bzb-J7m90FLG4QpjVlQ6LolP-ZulJ2ubHqIjsSFhPM4IPm2BbGPWM81U8hyv6v17Amoi5zaBYCpwDdel15U3yP63HZiFqg2Zm3SMimB-Rqk7KRhFEzX4w',
    d: 'FdYwElcsqWPHP_FQe6XCcsHhJtEkr48hhsSKNxXRwjjhXDY9Cp9m3q_uDbeUKc8vPcTDzAW6dO32_Skokx1JP8JhyWkfen77lbN9c0gJPr4oLSMFgXFBpb7CE3e_x8w6fifA6xaeg2l3Vw-dkx4geMPbEAwAlnoTPxQsN_2YiQvach48DnP5NVD4OquCvb4LgVrzqG-iRvhQIGYmUM921gpMt5weGkQn08ewMU-PqjbN8_UiL7t_N1jhp1eAQziX3vyml7WRcki0RcvLDnFEJeZ3L5hqsoFifSZ_--1d0ajs2f5Ytwq61E1RGijnw_7gmBnO6QvF6XotERZB6MIxAQ',
    p: '5o8PeEkdHLCWTKX8aKWl9ug2BnSMz1wI9V8tsvl_1J-YIhW66t03qLLo7Xhq7BIEJ22StPVeZ_5kwST2qHDhe0jpDKi6hu58xXZWT5BZ61jeBkiyJBIEE0dv0Ippn12bnPV_2up44gYodbZtXWbthqvEo2ODpI6XyT9gd2aK2q0',
    q: 'yq6WDJ0Yk4VhsP8dB3xfJ3sjaISux49KmoVkmItqIx64SMYKGpkTkq6fbSl8C9EsrUEsSqOMtRmcrDIl3EE5v24hf2nSUODXaMn7qpChOKnp9vGAB0TFgHhr9jo7yuIwVMtlZsPFhKR4uz03-dDy9ggqhXDH261huurOQ5J03s8',
    dp: 'yyEHtCZWa8x43xbuhxRKYHq9_nn5BUhE7Enq7WA8a4wgcQdMI1i7jPnzliUdrtdAqaw0MRJtFppfEnwKhOTPA9t82BZgIDlF3IMiD_9R-bPWCRtLN9RXmtS5grYv0KScUXFKMAmcbyaVxv_u4veoFZqIKJuog_bNbBVWXFwPwhE',
    dq: 'UKpJV73SQSwtpEb0Y71RFaKBhiCAezYBSBxc3AVoeY_JYlVHQiy4SIGtO8Ht97oJYO72VMJgxtbprvLKdK2U8SZAuLgCF2RU9wSkX87uC2I8lqapALuTKz1CIp4sm-OHvsewlMTHwLHAxyxnMcrCV78KRU-Mi1am9cBr1SLd1qs',
    qi: 'b31N6vZCVqaXFBUydvlOiUdiIBhLaGsaDyoDyYEeP99JOKWXDmx60qtf8OPxDOciES7jlR_Ay2MWGEtrZYEHziAbHKjZjFdR3cofnqh3lqDjyNxzbLRlhZOWpdZ0zSI7MXIMipVTMnVeKPzu4R1z464h31CNP5rdNEq_dSfYBv0',
    alg: 'RS256',
    ext: true 
};

describe('#signing', () => {

    it('should generate a key pair', async () => {
        const keys = await ne14.crypto.gen();
        expect(keys.publicJwk || '').to.not.equal('');
        expect(keys.privateJwk || '').to.not.equal('');
    });

    it('should reproducibly sign text', async () => {
        const sig = await ne14.crypto.sign('hello world', TEST_KEY);
        expect(sig || '').to.equal('Ug_CoHjDr8Ovw4bDkcKWwpTCvcObSEjDjMKGA1gjw4Mqw6g6YwjCoMOOemIzwpVtw6cFVy3CiRzDvQ94woPDv3bCpkxlFMO4PsKpUMKJcmtgMzDCs8KFAsKoD3cFw5YrahQOwpXChMKrJwTDjiVGVsKheX_DrsK2wpFZw69LwoQ1wop5IcO8wqTCncO-MXHDmcOqbi_DgQHCtRgIw5HDrMKzw4ptEXDCtMKuwqBoScOSw5EhQTApwrAPUcKyw53DnSEpdVXDiSjCs8KIUMOaw47Csm1WwobColTDqw7Ch0w9w4fCpMOxL8KFw4rCi2jCncOVQXlJDcK6TC86HsK5HsKXZxNRCGY8OcOHw6Brwod_w6HCk8OjcDvCsT4bw4fCqMKjOMOxLy_Dp2RPw5xQOcODw617w5XDlXHDlzYrPEfDvwPCiMKlwqDCp8OINcKzZmbCuTdwPxHCpFHCu8KWBMOYwp1ewrIQw5cIE8KZGsOsLinChsOe');
    });

    it ('should create a csr', async () => {
        const params = { domain: 'test.org' },
              sut = await ne14.crypto.csr(params);

        console.log(sut);
    });
});