import { MAX_SCOPE } from './auth/scopes';

let snowflakeInc = 0;
const incrementWidth = 6;
const epoch = new Date('2023-01-01 0:00:00').getTime();

// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
BigInt.prototype.toJSON = function () {
    return this.toString();
};

export function createSnowflake() {
    const timestamp = Date.now() - epoch;
    const inc = snowflakeInc++ % (1 << incrementWidth);
    return (BigInt(timestamp) << BigInt(incrementWidth)) + BigInt(inc);
}

export function getSnowflakeDate(snowflake: bigint): number {
    return Number(snowflake >> BigInt(incrementWidth)) + epoch;
}

export const timeStrToMillis = (timeString: string) =>
    timeString.match(/\d+\s?\w/g).reduce((acc, cur) => {
        let multiplier = 1000;
        switch (cur.slice(-1)) {
            case 'h':
                multiplier *= 60;
            case 'm':
                multiplier *= 60;
            case 's':
                return (parseInt(cur) ? parseInt(cur) : 0) * multiplier + acc;
        }
        return acc;
    }, 0);

export function limitScopeToMax(scope: number) {
    return scope & MAX_SCOPE;
}

export enum TokenLevel {
    ACCOUNT = 0,
    OAUTH = 1,
    OAUTH_SUBTOKEN = 2,
}