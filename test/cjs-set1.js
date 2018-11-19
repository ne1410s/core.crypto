const expect = require('chai').expect;
const MyTest = require('../dist/ne14.crypto');

describe('#thingamy', () => {

    it('1.1.1', () => {

        let test = new MyTest(3);
        console.log(test);

        expect(test.area).to.equal(3.141592 * 9);
    });

});