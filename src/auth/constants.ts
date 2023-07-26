import { randomBytes } from "crypto";

export const jwtConstants = {
    accessSecret: Buffer.from(process.env.JWT_ACCESS_SECRET, 'base64') || randomBytes(256).toString('base64'),
    accessExpiry: '6h',

    refreshSecret: Buffer.from(process.env.JWT_REFRESH_SECRET, 'base64') || randomBytes(256).toString('base64'),
    refreshExpiry: '30d',

    authCodeExpiry: '30s',

    deviceCodeSecret: Buffer.from(process.env.JWT_DEVICE_SECRET, 'base64') || randomBytes(256).toString('base64'),
    deviceCodeExpiry: '5m',
};