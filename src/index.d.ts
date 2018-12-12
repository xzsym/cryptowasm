export interface Math {
    add(a: number, b: number): number;
    factorial(a: number): number;
    fibonacci(a: number): number;
}

export interface Empty {
    empty: string;
}

declare module 'cryptowasm' {
    export function getMath(): Promise<Math>;
    export function getEmpty(): Promise<Empty>;
}

