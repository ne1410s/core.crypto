import { Pi } from './constants';

export default class MyTest {
    
    public area: number;
    public circumference: number;

    constructor(public radius: number) {
        this.area = Pi * this.radius * this.radius;
        this.circumference = Pi * this.radius * 2;
    }

}