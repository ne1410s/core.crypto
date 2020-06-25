const expect = require('chai').expect;
const ne_crypto = require('../dist/ne14_crypto.umd.min');
const fs = require('fs');

const TEST_KEY = {
  kty: 'RSA',
  key_ops: ['sign'],
  e: 'AQAB',
  n:
    'tooelJyzvanRGeEwfRGzemT11cGuhVlfzP-CeCoVrthpLbOAjPHxTxyg1mNTox0HvLwh_CGl9t7z0xL-1Vm-EzAdpGe8MyZWW2X6_yJeQx17qq8bUCfOmJF_BxzXO_OJOH9yglX-wpyQNo_TKJxUVt4qch_j3mOVMmW5WBeHAj1dlS3Rl1Imlm6BrqAlM88WAmJ6k_wzWN0yqLHcdv8dihs3uIgU0lGR2Bzb-J7m90FLG4QpjVlQ6LolP-ZulJ2ubHqIjsSFhPM4IPm2BbGPWM81U8hyv6v17Amoi5zaBYCpwDdel15U3yP63HZiFqg2Zm3SMimB-Rqk7KRhFEzX4w',
  d:
    'FdYwElcsqWPHP_FQe6XCcsHhJtEkr48hhsSKNxXRwjjhXDY9Cp9m3q_uDbeUKc8vPcTDzAW6dO32_Skokx1JP8JhyWkfen77lbN9c0gJPr4oLSMFgXFBpb7CE3e_x8w6fifA6xaeg2l3Vw-dkx4geMPbEAwAlnoTPxQsN_2YiQvach48DnP5NVD4OquCvb4LgVrzqG-iRvhQIGYmUM921gpMt5weGkQn08ewMU-PqjbN8_UiL7t_N1jhp1eAQziX3vyml7WRcki0RcvLDnFEJeZ3L5hqsoFifSZ_--1d0ajs2f5Ytwq61E1RGijnw_7gmBnO6QvF6XotERZB6MIxAQ',
  p:
    '5o8PeEkdHLCWTKX8aKWl9ug2BnSMz1wI9V8tsvl_1J-YIhW66t03qLLo7Xhq7BIEJ22StPVeZ_5kwST2qHDhe0jpDKi6hu58xXZWT5BZ61jeBkiyJBIEE0dv0Ippn12bnPV_2up44gYodbZtXWbthqvEo2ODpI6XyT9gd2aK2q0',
  q:
    'yq6WDJ0Yk4VhsP8dB3xfJ3sjaISux49KmoVkmItqIx64SMYKGpkTkq6fbSl8C9EsrUEsSqOMtRmcrDIl3EE5v24hf2nSUODXaMn7qpChOKnp9vGAB0TFgHhr9jo7yuIwVMtlZsPFhKR4uz03-dDy9ggqhXDH261huurOQ5J03s8',
  dp:
    'yyEHtCZWa8x43xbuhxRKYHq9_nn5BUhE7Enq7WA8a4wgcQdMI1i7jPnzliUdrtdAqaw0MRJtFppfEnwKhOTPA9t82BZgIDlF3IMiD_9R-bPWCRtLN9RXmtS5grYv0KScUXFKMAmcbyaVxv_u4veoFZqIKJuog_bNbBVWXFwPwhE',
  dq:
    'UKpJV73SQSwtpEb0Y71RFaKBhiCAezYBSBxc3AVoeY_JYlVHQiy4SIGtO8Ht97oJYO72VMJgxtbprvLKdK2U8SZAuLgCF2RU9wSkX87uC2I8lqapALuTKz1CIp4sm-OHvsewlMTHwLHAxyxnMcrCV78KRU-Mi1am9cBr1SLd1qs',
  qi:
    'b31N6vZCVqaXFBUydvlOiUdiIBhLaGsaDyoDyYEeP99JOKWXDmx60qtf8OPxDOciES7jlR_Ay2MWGEtrZYEHziAbHKjZjFdR3cofnqh3lqDjyNxzbLRlhZOWpdZ0zSI7MXIMipVTMnVeKPzu4R1z464h31CNP5rdNEq_dSfYBv0',
  alg: 'RS256',
  ext: true,
};

describe('#signing', () => {
  it('should generate a key pair', async () => {
    const keys = await ne_crypto.gen();
    expect(keys.publicJwk || '').to.not.equal('');
    expect(keys.privateJwk || '').to.not.equal('');
  });

  it('should correctly sign text', async () => {
    const sig = await ne_crypto.sign('hello world', TEST_KEY);
    expect(sig || '').to.equal(
      'Ug-geO_vxtGWlL3bSEjMhgNYI8Mq6DpjCKDOemIzlW3nBVctiRz9D3iD_3amTGUU-D6pUIlya2AzMLOFAqgPdwXWK2oUDpWEqycEziVGVqF5f-62kVnvS4Q1inkh_KSd_jFx2epuL8EBtRgI0eyzym0RcLSuoGhJ0tEhQTApsA9Rst3dISl1Vckos4hQ2s6ybVaGolTrDodMPcek8S-FyotondVBeUkNukwvOh65HpdnE1EIZjw5x-Brh3_hk-NwO7E-G8eoozjxLy_nZE_cUDnD7XvV1XHXNis8R_8DiKWgp8g1s2ZmuTdwPxGkUbuWBNidXrIQ1wgTmRrsLimG3g'
    );
  });

  it('should create a csr', async () => {
    const sut = await ne_crypto.csr({
      domains: ['test.org', 'test.co.uk', 'thingz.biz'],
      county: 'Shropshire',
      town: 'Salisbury',
      company: 'TestCo',
      department: 'Things',
      country: 'UK',
    });

    console.log(sut);
  });

  it('should create a pkcs12 file', async () => {
    const name = 'Test Cert!',
      cert_b64 =
        'MIIDRDCCAi6gAwIBAgIBATALBgkqhkiG9w0BAQswODE2MAkGA1UEBhMCVVMwKQYDVQQDHiIAUABlAGMAdQBsAGkAYQByACAAVgBlAG4AdAB1AHIAZQBzMB4XDTEzMDEzMTIxMDAwMFoXDTE2MDEzMTIxMDAwMFowODE2MAkGA1UEBhMCVVMwKQYDVQQDHiIAUABlAGMAdQBsAGkAYQByACAAVgBlAG4AdAB1AHIAZQBzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4qEnCuFxZqTEM/8cYcaYxexT6+fAHan5/eGCFOe1Yxi0BjRuDooWBPX71+hmWK/MKrKpWTpA3ZDeWrQR2WIcaf/ypd6DAEEWWzlQgBYpEUj/o7cykNwIvZReU9JXCbZu0EmeZXzBm1mIcWYRdk17UdneIRUkU379wVJcKXKlgZsx8395UNeOMk11G5QaHzAafQ1ljEKB/x2xDgwFxNaKpSIq3LQFq0PxoYt/PBJDMfUSiWT5cFh1FdKITXQzxnIthFn+NVKicAWBRaSZCRQxcShX6KHpQ1Lmk0/7QoCcDOAmVSfUAaBl2w8bYpnobFSStyY0RJHBqNtnTV3JonGAHwIDAQABo10wWzAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIA/zAdBgNVHQ4EFgQU5QmA6U960XL4SII2SEhCcxij0JYwHwYDVR0jBBgwFoAU5QmA6U960XL4SII2SEhCcxij0JYwCwYJKoZIhvcNAQELA4IBAQAikQls3LhY8rYQCZ+8jXrdaRTY3L5J3S2xzoAofkEnQNzNMClaWrZbY/KQ+gG25MIFwPOWZn/uYUKB2j0yHTRMPEAp/v5wawSqM2BkdnkGP4r5Etx9pe3mog2xNUBqSeopNNto7QgV0o1yYHtuMKQhNAzcFB1CGz25+lXv8VuuU1PoYNrTjiprkjLDgPurNXUjUh9AZl06+Cakoe75LEkuaZKuBQIMNLJFcM2ZSK/QAAaI0E1DovcsCctW8x/6Qk5fYwNu0jcIdng9dzKYXytzV53+OGxdK5mldyBBkyvTrbO8bWwYT3c+weB1huNpgnpRHJKMz5xVj0bbdnHir6uc',
      key_b64 =
        'MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDioScK4XFmpMQz/xxhxpjF7FPr58Adqfn94YIU57VjGLQGNG4OihYE9fvX6GZYr8wqsqlZOkDdkN5atBHZYhxp//Kl3oMAQRZbOVCAFikRSP+jtzKQ3Ai9lF5T0lcJtm7QSZ5lfMGbWYhxZhF2TXtR2d4hFSRTfv3BUlwpcqWBmzHzf3lQ144yTXUblBofMBp9DWWMQoH/HbEODAXE1oqlIirctAWrQ/Ghi388EkMx9RKJZPlwWHUV0ohNdDPGci2EWf41UqJwBYFFpJkJFDFxKFfooelDUuaTT/tCgJwM4CZVJ9QBoGXbDxtimehsVJK3JjREkcGo22dNXcmicYAfAgMBAAECggEBANMO1fdyIVRAWmE6UspUU+7vuvBWMjruE9126NhjOjABz5Z/uYdc3kjcdSCMVNR/VBrnrINmlwZBZnL+hCj5EBE/xlDnOwU/mHx4khnXiYOJglqLwFHcOV+lD3vsxhZLikP8a8GEQCJXbZR+RADzA8gkqJQSxnPkLpqeAyqulKhviQ2lq2ZxeCXI+iZvURQPTSm86+szClwgzr2uW6NSlNKKeeLHMILed4mrwbPOdyhutnqvV79GUYH3yYdzbEbbw5GOat77+xPLt33cfLCL7pg5lGDrKEomu6V1d5KmBOhv0K8gGPKfxPrpeUG5n1q58k/2ouCiyAaKWpVoOWmnbzECgYEA/UzAGZ2N8YE+kC85Nl0wQof+WVm+RUDsv6C3L2vPUht3GwnbxSTMl4+NixbCWG46udVhsM2x7ZzYY1eB7LtnBnjvXZTYU4wqZtGR/+X2Rw5ou+oWm16/OgcEuFjP2zpQtr9r/bpKhyBV+IdSngnLy00RueKGUL6nvtecRklEhQ0CgYEA5Quek+c12qMtrmg5znHPQC7uuieZRzUL9jTlQtuZM5m4B3AfB/N/0qIQS06PHS1ijeHQ9SxEmG72weamUYC0SPi8GxJioFzaJEDVit0Ra38gf0CXQvcYT0XD1CwY/m+jDXDWL5L1CCIr60AzNjM3WEfGO4VHaNsovVLn1Fvy5tsCgYEA4ZOEUEubqUOsb8NedCexXs61mOTvKcWUEWQTP0wHqduDyrSQ35TSDvds2j0+fnpMGksJYOcOWcmge3fm4OhT69Ovd+uia2UcLczc9MPa+5S9ePwTffJ24jp13aZaFaZtUxJOHfvVe1k0tsvsq4mV0EumSaCOdUIVKUPijEWbm9ECgYBpFa+nxAidSwiGYCNFaEnh9KZqmghk9x2J1DLrPb1IQ1p/bx2NlFYs2VYIdv6KMGxrFBO+qJTAKwjjZWMhOZ99a0FCWmkNkgwzXdubXlnDrAvI1mWPv7ZTiHqUObct5SI15HMgWJg7JxJnWIkmcNEPm76DSF6+6O4EDql2cMk8yQKBgF5roj+l90lfwImr6V1NJo3J5VCi9wTT5x9enPY9WRcfSyRjqU7JWy6h0C+Jq+AYAxrkQVjQuv1AOhO8Uhc6amM5FA+gfg5HKKPnwuOe7r7B48LFF8eRjYRtHmrQUrFY0jH6O+t12dEQI+7qE+SffUScsZWCREX7QYEK/tuznv/U',
      password = 'abcDEF123!',
      sut = await ne_crypto.pfx(name, cert_b64, key_b64, password);

    fs.appendFileSync('test/test-cert.p12', Buffer.from(sut), (err) => console.log(err));
  }).timeout(0);

  it('should format base 64 as pem and vice versa', async () => {
    const b64 =
        'MIIDRDCCAi6gAwIBAgIBATALBgkqhkiG9w0BAQswODE2MAkGA1UEBhMCVVMwKQYDVQQDHiIAUABlAGMAdQBsAGkAYQByACAAVgBlAG4AdAB1AHIAZQBzMB4XDTEzMDEzMTIxMDAwMFoXDTE2MDEzMTIxMDAwMFowODE2MAkGA1UEBhMCVVMwKQYDVQQDHiIAUABlAGMAdQBsAGkAYQByACAAVgBlAG4AdAB1AHIAZQBzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4qEnCuFxZqTEM/8cYcaYxexT6+fAHan5/eGCFOe1Yxi0BjRuDooWBPX71+hmWK/MKrKpWTpA3ZDeWrQR2WIcaf/ypd6DAEEWWzlQgBYpEUj/o7cykNwIvZReU9JXCbZu0EmeZXzBm1mIcWYRdk17UdneIRUkU379wVJcKXKlgZsx8395UNeOMk11G5QaHzAafQ1ljEKB/x2xDgwFxNaKpSIq3LQFq0PxoYt/PBJDMfUSiWT5cFh1FdKITXQzxnIthFn+NVKicAWBRaSZCRQxcShX6KHpQ1Lmk0/7QoCcDOAmVSfUAaBl2w8bYpnobFSStyY0RJHBqNtnTV3JonGAHwIDAQABo10wWzAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIA/zAdBgNVHQ4EFgQU5QmA6U960XL4SII2SEhCcxij0JYwHwYDVR0jBBgwFoAU5QmA6U960XL4SII2SEhCcxij0JYwCwYJKoZIhvcNAQELA4IBAQAikQls3LhY8rYQCZ+8jXrdaRTY3L5J3S2xzoAofkEnQNzNMClaWrZbY/KQ+gG25MIFwPOWZn/uYUKB2j0yHTRMPEAp/v5wawSqM2BkdnkGP4r5Etx9pe3mog2xNUBqSeopNNto7QgV0o1yYHtuMKQhNAzcFB1CGz25+lXv8VuuU1PoYNrTjiprkjLDgPurNXUjUh9AZl06+Cakoe75LEkuaZKuBQIMNLJFcM2ZSK/QAAaI0E1DovcsCctW8x/6Qk5fYwNu0jcIdng9dzKYXytzV53+OGxdK5mldyBBkyvTrbO8bWwYT3c+weB1huNpgnpRHJKMz5xVj0bbdnHir6uc',
      sut = await ne_crypto.base64ToPem(b64, '  wowzers ');

    expect(sut.indexOf('-----BEGIN WOWZERS-----')).to.equal(0);

    const sut2 = `\r\n${sut}\r\n\r\n${sut}\r\n`,
      e2e = ne_crypto.pemToBase64Parts(sut2);

    expect(e2e.length).to.equal(2);
    expect(e2e[1].indexOf('MIIDRDCCAi6gAwIBAgIBATA')).to.equal(0);
  });

  it('should generate a random string', async () => {
    const sut = await ne_crypto.randomString();
    expect(sut.length).to.equal(32);
  });
});
