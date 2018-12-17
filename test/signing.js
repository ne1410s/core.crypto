const expect = require('chai').expect;
const ne14 = {
    crypto: require('../dist/index')
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

    it('should correctly sign text', async () => {
        const sig = await ne14.crypto.sign('hello world', TEST_KEY);
        expect(sig || '').to.equal('Ug-geO_vxtGWlL3bSEjMhgNYI8Mq6DpjCKDOemIzlW3nBVctiRz9D3iD_3amTGUU-D6pUIlya2AzMLOFAqgPdwXWK2oUDpWEqycEziVGVqF5f-62kVnvS4Q1inkh_KSd_jFx2epuL8EBtRgI0eyzym0RcLSuoGhJ0tEhQTApsA9Rst3dISl1Vckos4hQ2s6ybVaGolTrDodMPcek8S-FyotondVBeUkNukwvOh65HpdnE1EIZjw5x-Brh3_hk-NwO7E-G8eoozjxLy_nZE_cUDnD7XvV1XHXNis8R_8DiKWgp8g1s2ZmuTdwPxGkUbuWBNidXrIQ1wgTmRrsLimG3g');
    });

    it ('should create a csr', async () => {
        const params = { domains: ['test.org', 'test.co.uk'] },
              sut = await ne14.crypto.csr(params);

        console.log(sut);
    });
});