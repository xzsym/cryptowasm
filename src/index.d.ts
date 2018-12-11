export interface Math {
    add(a: number, b: number): number;
    factorial(a: number): number;
    fibonacci(a: number): number;
}

declare module 'cryptowasm' {
    export default function(): Promise<Math>; }

