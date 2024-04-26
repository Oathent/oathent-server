// TOTP

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

// WebAuthn

import type {
    PublicKeyCredentialCreationOptionsJSON,
    RegistrationResponseJSON,
    PublicKeyCredentialRequestOptionsJSON,
    AuthenticationResponseJSON,
} from '@simplewebauthn/types';

import {
    VerifiedRegistrationResponse,
    generateAuthenticationOptions,
    generateRegistrationOptions,
    verifyAuthenticationResponse,
    verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { protocolPorts } from "./email";
import { Passkey, User } from "@prisma/client";

const rpName = process.env.WEB_AUTHN_RP_NAME ?? 'Oathent Server';
const rpID = process.env.WEB_AUTHN_RP_ID ?? process.env.SERVER_ADDRESS ?? 'localhost';
const origin = process.env.WEB_AUTHN_RP_ORIGIN ?? process.env.SERVER_ADDRESS ?? 'localhost';

const webAuthnRegistrationOptions = new Map<bigint, PublicKeyCredentialCreationOptionsJSON>();
const webAuthnAuthenticationOptions = new Map<bigint, PublicKeyCredentialRequestOptionsJSON>();

export async function generateWebAuthnRegistrationOptions(user: User, existingPasskeys: Passkey[]): Promise<{ success: boolean, options?: PublicKeyCredentialCreationOptionsJSON }> {
    try {
        const options: PublicKeyCredentialCreationOptionsJSON = await generateRegistrationOptions({
            rpName,
            rpID,
            userName: user.username,
            // Don't prompt users for additional information about the authenticator
            // (Recommended for smoother UX)
            attestationType: 'none',
            // Prevent users from re-registering existing authenticators
            excludeCredentials: existingPasskeys.map(passkey => ({
                id: passkey.id,
            })),
            // See "Guiding use of authenticators via authenticatorSelection" below
            authenticatorSelection: {
                // Defaults
                residentKey: 'preferred',
                userVerification: 'preferred',
            },
        });

        // Remember these options for the user
        webAuthnRegistrationOptions.set(user.id, options);

        return { success: true, options };
    } catch (error) {
        return { success: false };
    }
}

export async function verifyWebAuthnRegistrationResponse(user: User, response: RegistrationResponseJSON): Promise<{ success: boolean, verification?: VerifiedRegistrationResponse }> {
    const currentOptions = webAuthnRegistrationOptions.get(user.id);

    try {
        let verification = await verifyRegistrationResponse({
            response,
            expectedChallenge: currentOptions.challenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            requireUserVerification: currentOptions.authenticatorSelection?.userVerification === 'required',
        });

        return { success: verification.verified, verification };
    } catch (error) {
        return { success: false };
    }
}

export async function generateWebAuthnAuthenticationOptions(user: User, existingPasskeys: Passkey[]): Promise<{ success: boolean, options?: PublicKeyCredentialRequestOptionsJSON }> {
    try {
        const options: PublicKeyCredentialRequestOptionsJSON = await generateAuthenticationOptions({
            rpID,
            // Require users to use a previously-registered authenticator
            allowCredentials: existingPasskeys.map(passkey => ({
                id: passkey.id,
            })),
        });

        // Remember these options for the user
        webAuthnAuthenticationOptions.set(user.id, options);

        return { success: true, options };
    } catch (error) {
        return { success: false };
    }
}

export async function webAuthnIsValid(userId: bigint, existingPasskeys: Passkey[], credential: string): Promise<boolean> {
    if (!existingPasskeys.length) {
        return false;
    }

    try {
        const body: AuthenticationResponseJSON = JSON.parse(credential);
        const currentOptions = webAuthnAuthenticationOptions.get(userId);

        let passkey = existingPasskeys.find(passkey => passkey.id === body.id);

        let verification = await verifyAuthenticationResponse({
            response: body,
            expectedChallenge: currentOptions.challenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            requireUserVerification: currentOptions.userVerification === 'required',
            authenticator: {
                credentialID: passkey.id,
                credentialPublicKey: passkey.publicKey,
                counter: Number(passkey.counter),
            },
        });

        return verification.verified;
    } catch (e) {
        return false;
    }
}