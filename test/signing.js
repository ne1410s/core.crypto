const expect = require('chai').expect;
const ne14 = {
    crypto: require('../dist/index')
};

describe('#signing', () => {

    it('should reference the text module :)', () => {

        let result = ne14.crypto.check();
        console.log(result);

        expect(result).to.equal('aGVsbG8gd29ybGQ=');
    });

});