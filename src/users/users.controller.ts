import { Request, Controller, Get } from '@nestjs/common';
import { Token, UseAuth } from '../auth/auth.guard';
import { ProfileResponse } from '../entities/auth.entity';
import { ApiTags, ApiOperation, ApiOkResponse } from '@nestjs/swagger';
import { scopeIncludes } from 'src/auth/scopes';
import { RateLimit, RateLimitEnv } from 'src/ratelimit.guard';

@ApiTags('user')
@Controller('user')
export class UsersController {
    @ApiOperation({ summary: 'View user profile' })
    @ApiOkResponse({ description: 'User profile', type: ProfileResponse })
    @RateLimit(RateLimitEnv('user/profile', 25))
    @UseAuth(Token.ACCESS)
    @Get('profile')
    getProfile(@Request() req) {
        return {
            id: req.user.id,
            username: req.user.username,
            email:
                req.auth.appId == null ||
                scopeIncludes(req.auth.scope, 'user:email')
                    ? req.user.email
                    : undefined,
            verified: req.user.verified,
        };
    }
}
