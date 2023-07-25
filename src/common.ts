let snowflakeInc = 0;
const incrementWidth = 6;
const epoch = new Date("2023-01-01 0:00:00").getTime();

// @ts-ignore
BigInt.prototype.toJSON = function () {
    return this.toString();
};

export function createSnowflake() {
    let timestamp = Date.now() - epoch;
    let inc = snowflakeInc++ % (1 << incrementWidth);
    return (BigInt(timestamp) << BigInt(incrementWidth)) + BigInt(inc);
}

export function getSnowflakeDate(snowflake: bigint): number {
    return Number(snowflake >> BigInt(incrementWidth)) + epoch;
}

export const timeStrToMillis = (timeString: string) => timeString.match(/\d+\s?\w/g)
    .reduce((acc, cur, i) => {
        var multiplier = 1000;
        switch (cur.slice(-1)) {
            case 'h':
                multiplier *= 60;
            case 'm':
                multiplier *= 60;
            case 's':
                return ((parseInt(cur) ? parseInt(cur) : 0) * multiplier) + acc;
        }
        return acc;
    }, 0);