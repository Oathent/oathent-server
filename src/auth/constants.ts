import { randomBytes } from "crypto";

export const jwtConstants = {
    accessSecret: process.env.JWT_ACCESS_SECRET ? Buffer.from(process.env.JWT_ACCESS_SECRET, 'base64') : randomBytes(256).toString('base64'),
    accessExpiry: process.env.JWT_ACCESS_EXPIRY || '6h',

    refreshSecret: process.env.JWT_REFRESH_SECRET ? Buffer.from(process.env.JWT_REFRESH_SECRET, 'base64') : randomBytes(256).toString('base64'),
    refreshExpiry: process.env.JWT_REFRESH_EXPIRY || '30d',

    authCodeExpiry: process.env.JWT_AUTH_CODE_EXPIRY || '30s',

    deviceCodeSecret: process.env.JWT_DEVICE_CODE_SECRET ? Buffer.from(process.env.JWT_DEVICE_CODE_SECRET, 'base64') : randomBytes(256).toString('base64'),
    deviceCodeExpiry: process.env.JWT_DEVICE_CODE_EXPIRY || '5m',

    verifyCodeSecret: process.env.JWT_VERIFY_CODE_SECRET ? Buffer.from(process.env.JWT_VERIFY_CODE_SECRET, 'base64') : randomBytes(256).toString('base64'),
    verifyCodeExpiry: process.env.JWT_VERIFY_CODE_EXPIRY || '1d',
};