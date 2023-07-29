import { Throttle, ThrottlerGuard } from '@nestjs/throttler';
import { Injectable, UseGuards, applyDecorators } from '@nestjs/common';

export const RateLimit = (limit?: number, ttl?: number) => {
    return applyDecorators(
        UseGuards(ThrottlerBehindProxyGuard),
        Throttle(limit, ttl),
    );
};

@Injectable()
class ThrottlerBehindProxyGuard extends ThrottlerGuard {
    protected getTracker(req: Record<string, any>): string {
        if (req.user) {
            if (req.auth && req.auth.appId)
                return req.user.id + '@' + req.auth.appId;
            else return req.user.id;
        }
        return req.ips.length ? req.ips[0] : req.ip;
    }
}

export function RateLimitEnv(path: string, fallback: number) {
    const envVal =
        process.env['RATE_LIMIT_' + path.toUpperCase().replaceAll('/', '_')];
    return envVal && !isNaN(Number(envVal)) ? Number(envVal) : fallback;
}
