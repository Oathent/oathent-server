import { randomBytes } from "crypto";

export const jwtConstants = {
    accessSecret: Buffer.from(process.env.JWT_ACCESS_SECRET, 'base64') || randomBytes(256).toString('base64'),
    accessExpiry: process.env.JWT_ACCESS_EXPIRY || '6h',

    refreshSecret: Buffer.from(process.env.JWT_REFRESH_SECRET, 'base64') || randomBytes(256).toString('base64'),
    refreshExpiry: process.env.JWT_REFRESH_EXPIRY || '30d',

    authCodeExpiry: process.env.JWT_AUTH_CODE_EXPIRY || '30s',

    deviceCodeSecret: Buffer.from(process.env.JWT_DEVICE_CODE_SECRET, 'base64') || randomBytes(256).toString('base64'),
    deviceCodeExpiry: process.env.JWT_DEVICE_CODE_EXPIRY || '5m',
};