import {
    Throttle,
    ThrottlerException,
    ThrottlerGuard,
} from '@nestjs/throttler';
import {
    ExecutionContext,
    Injectable,
    UseGuards,
    applyDecorators,
} from '@nestjs/common';

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

    protected async handleRequest(context: ExecutionContext, limit: number, ttl: number): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        if (process.env.RATE_LIMIT_BYPASS_KEY && request.headers['rate-limit-bypass-key'] == process.env.RATE_LIMIT_BYPASS_KEY) {
            return true;
        }

        return await super.handleRequest(context, limit, ttl);
    }

    protected throwThrottlingException(context: ExecutionContext) {
        throw new ThrottlerException('Too many requests');
    }
}

export function RateLimitEnv(path: string, fallback: number) {
    const envVal =
        process.env['RATE_LIMIT_' + path.toUpperCase().replaceAll('/', '_')];
    return envVal && !isNaN(Number(envVal)) ? Number(envVal) : fallback;
}
