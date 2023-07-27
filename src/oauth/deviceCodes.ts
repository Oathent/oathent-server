import { timeStrToMillis } from 'src/common';
import { jwtConstants } from 'src/auth/constants';

export type DeviceCodeStatus = 'waiting' | 'redeemed' | 'rejected' | 'authed';

interface DeviceCodeInfo {
    status: DeviceCodeStatus;
    userId: bigint;
    appId: bigint;
    scope: number;
    expiry: number;
}

const deviceCodes: { [key: string]: DeviceCodeInfo } = {};

export function getDeviceCodeStatus(deviceCode: string): DeviceCodeStatus {
    return deviceCodes[deviceCode] ? deviceCodes[deviceCode].status : 'waiting';
}

export function addDeviceCodeInfo(
    deviceCode: string,
    status: DeviceCodeStatus,
    userId: bigint,
    appId: bigint,
    scope: number,
    expiry: number,
) {
    deviceCodes[deviceCode] = {
        status,
        userId,
        appId,
        scope,
        expiry,
    };
}

export function setDeviceCodeStatus(
    deviceCode: string,
    status: DeviceCodeStatus,
) {
    if (deviceCodes[deviceCode]) deviceCodes[deviceCode].status = status;
}

export function getDeviceCodeInfo(deviceCode: string): DeviceCodeInfo {
    return deviceCodes[deviceCode];
}

async function purgeDeviceCodes() {
    for (const code in deviceCodes) {
        if (deviceCodes[code].status !== 'waiting')
            return delete deviceCodes[code];

        if (deviceCodes[code].expiry < Date.now())
            return delete deviceCodes[code];
    }
}

setInterval(purgeDeviceCodes, timeStrToMillis(jwtConstants.deviceCodeExpiry));
