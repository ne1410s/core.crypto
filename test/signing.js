const expect = require('chai').expect;
const ne14 = {
    crypto: require('../dist/index')
};

describe('#signing', () => {

    it('should generate a key pair', async () => {
        let keys = await ne14.crypto.gen();
        console.log(keys);
    });
});