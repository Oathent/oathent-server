import { createHmac, randomBytes, timingSafeEqual } from "crypto";

function base32Encode(buf: Buffer, padding?: boolean) {
    // RFC3548 encoding
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let bits = 0
    let value = 0
    let output = ''

    for (let i = 0; i < buf.byteLength; i++) {
        value = (value << 8) | buf[i]
        bits += 8

        while (bits >= 5) {
            output += alphabet[(value >>> (bits - 5)) & 31]
            bits -= 5
        }
    }

    if (bits > 0) {
        output += alphabet[(value << (5 - bits)) & 31]
    }

    if (padding) {
        while ((output.length % 8) !== 0) {
            output += '='
        }
    }

    return output;
}

function base32ToBuf(str: string): ArrayBuffer {
    // Canonicalize to all upper case and remove padding if it exists.
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let end = str.length;
    while (str[end - 1] === "=") --end;
    const cstr = (end < str.length ? str.substring(0, end) : str).toUpperCase();

    const buf = new ArrayBuffer(((cstr.length * 5) / 8) | 0);
    const arr = new Uint8Array(buf);
    let bits = 0;
    let value = 0;
    let index = 0;

    for (let i = 0; i < cstr.length; i++) {
        const idx = alphabet.indexOf(cstr[i]);
        if (idx === -1) throw new TypeError(`Invalid character found: ${cstr[i]}`);

        value = (value << 5) | idx;
        bits += 5;

        if (bits >= 8) {
            bits -= 8;
            arr[index++] = value >>> bits;
        }
    }

    return buf;
};

export function genTotpSecret(): string {
    const buf = randomBytes(32);
    return base32Encode(buf);
}

function hmacDigest(key: ArrayBuffer, message: ArrayBuffer) {
    const hmac = createHmac('sha1', Buffer.from(key));
    hmac.update(Buffer.from(message));
    return hmac.digest().buffer;
}

function uintToBuf(num: number): ArrayBuffer {
    const buf = new ArrayBuffer(8);
    const arr = new Uint8Array(buf);
    let acc = num;

    for (let i = 7; i >= 0; i--) {
        if (acc === 0) break;
        arr[i] = acc & 255;
        acc -= arr[i];
        acc /= 256;
    }

    return buf;
};

function generateHOTP(secret: ArrayBuffer, digits: number, counter: number): string {
    const digest = new Uint8Array(
        hmacDigest(secret, uintToBuf(counter)),
    );
    const offset = digest[digest.byteLength - 1] & 15;
    const otp =
        (((digest[offset] & 127) << 24) |
            ((digest[offset + 1] & 255) << 16) |
            ((digest[offset + 2] & 255) << 8) |
            (digest[offset + 3] & 255)) %
        10 ** digits;

    return otp.toString().padStart(digits, "0");
}

export function totpIsValid(token: string, secret: string): boolean {
    let counter = Math.floor(Date.now() / 1000 / 30);

    // Return early if the token length does not match the digit number.
    const digits = 6;
    if (token.length !== digits) return false;

    let delta = null;

    const secretBuf = base32ToBuf(secret);
    const window = 1;
    for (let i = counter - window; i <= counter + window; ++i) {
        const generatedToken = generateHOTP(secretBuf, digits, i);

        if (timingSafeEqual(Buffer.from(token), Buffer.from(generatedToken))) {
            delta = i - counter;
        }
    }

    return delta != null;
}