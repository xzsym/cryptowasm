export interface EcryptMeta {
    key: string;
    plaintext: string;
    podId: string;
    rotationId: string;
    usePassword: boolean;
    versionn: string;
}

declare module 'cryptowasm' {
    export function encrypt(meta: EcryptMeta): string;
    export function decrypt(key: string, content: string): string;
}

