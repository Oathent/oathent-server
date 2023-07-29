import {
    CanActivate,
    ExecutionContext,
    Injectable,
    UnauthorizedException,
    UseGuards,
    SetMetadata,
    applyDecorators,
    Inject,
    forwardRef,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { jwtConstants } from './constants';
import { Request } from 'express';
import { UsersService } from 'src/users/users.service';
import { Reflector } from '@nestjs/core';
import { OauthService } from 'src/oauth/oauth.service';
import {
    ApiBearerAuth,
    ApiForbiddenResponse,
    ApiOperation,
} from '@nestjs/swagger';
import { SCOPES, filterScopes } from './scopes';

export const AUTH_KEY_TYPE = 'authKeyType';
export const AUTH_OPT_SCOPES = 'authOptScopes';
export const AUTH_OPT_ACCOUNT = 'authOptAccount';
export const AUTH_OPT_VERIFIED = 'authOptVerified';

export enum Token {
    ACCESS = 'a',
    REFRESH = 'r',
    CODE = 'c',
    DEVICE_CODE = 'd',
    VERIFY_CODE = 'v',
    PASSWORD_RESET_CODE = 'p',
}

const tokenNames = {
    [Token.ACCESS]: 'access token',
    [Token.REFRESH]: 'refresh token',
    [Token.CODE]: 'auth code',
    [Token.DEVICE_CODE]: 'device code',
    [Token.VERIFY_CODE]: 'verification code',
};

export const UseAuth = (
    type?: Token,
    opts?: { account?: boolean; scopes?: string[]; verified?: boolean },
) => {
    const scopes = filterScopes(opts?.scopes);
    const apiDecorators: any[] = [
        ApiForbiddenResponse({ description: 'Forbidden' }),
    ];

    if (scopes.length > 0)
        apiDecorators.push(
            ApiOperation({
                description: `**Required scopes:** ${scopes.join(', ')}`,
            }),
        );

    if (type === Token.ACCESS || type === Token.REFRESH)
        apiDecorators.push(ApiBearerAuth(`Account ${tokenNames[type]}`));

    if (!opts || !opts.account)
        apiDecorators.push(ApiBearerAuth(`OAuth2 ${tokenNames[type]}`));

    return applyDecorators(
        ...apiDecorators,
        SetMetadata(AUTH_KEY_TYPE, type || Token.ACCESS),
        SetMetadata(AUTH_OPT_SCOPES, scopes),
        SetMetadata(AUTH_OPT_ACCOUNT, opts?.account || false),
        SetMetadata(AUTH_OPT_VERIFIED, opts?.verified || false),
        UseGuards(AuthGuard),
    );
};

@Injectable()
export class AuthGuard implements CanActivate {
    constructor(
        private jwtService: JwtService,
        @Inject(forwardRef(() => UsersService))
        private usersService: UsersService,
        @Inject(forwardRef(() => OauthService))
        private oauthService: OauthService,
        private reflector: Reflector,
    ) {}

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        const token = this.extractTokenFromHeader(request);
        if (!token) {
            throw new UnauthorizedException();
        }
        try {
            const authKeyType = this.reflector.getAllAndOverride<Token>(
                AUTH_KEY_TYPE,
                [context.getHandler(), context.getClass()],
            );
            const authOptScopes = this.reflector.getAllAndOverride<string[]>(
                AUTH_OPT_SCOPES,
                [context.getHandler(), context.getClass()],
            );
            const authOptAccount = this.reflector.getAllAndOverride<boolean>(
                AUTH_OPT_ACCOUNT,
                [context.getHandler(), context.getClass()],
            );
            const authOptVerified = this.reflector.getAllAndOverride<boolean>(
                AUTH_OPT_VERIFIED,
                [context.getHandler(), context.getClass()],
            );

            const data = await this.jwtService.decode(token);
            if (typeof data == 'string') throw new UnauthorizedException();

            let secret;
            switch (authKeyType) {
                case Token.ACCESS:
                    secret = jwtConstants.accessSecret;
                    break;
                case Token.REFRESH:
                    secret = jwtConstants.refreshSecret;
                    break;
                case Token.DEVICE_CODE:
                    secret = jwtConstants.deviceCodeSecret;
                    break;
                case Token.VERIFY_CODE:
                    secret = jwtConstants.verifyCodeSecret;
                    break;
                case Token.PASSWORD_RESET_CODE:
                    secret = jwtConstants.resetCodeSecret;
                    break;
                case Token.CODE:
                    request['oauthCode'] = {
                        userId: data.sub,
                        appId: data.app,
                        scope: data.scp,
                    };
                    break;
            }

            if (data.app) {
                if (
                    authOptAccount ||
                    !(await this.oauthService.hasAuthInfo(data.sub, data.app))
                )
                    throw new UnauthorizedException();

                const authInfo = await this.oauthService.getAuthInfo(
                    data.sub,
                    data.app,
                );
                secret = authInfo.jwtSecret;
            }

            const payload = await this.jwtService.verifyAsync(token, {
                secret,
            });

            if (
                payload.typ != authKeyType ||
                (payload.app &&
                    authOptScopes.reduce(
                        (p: boolean, c: string) =>
                            p || (payload.scp & SCOPES[c]) !== SCOPES[c],
                        false,
                    ))
            )
                throw new UnauthorizedException();

            if (authKeyType === Token.DEVICE_CODE) {
                request['deviceCode'] = token;
                return true;
            }

            if (!(await this.usersService.existsId(payload.sub)))
                throw new UnauthorizedException();

            const user = await this.usersService.findOneId(payload.sub);

            if (authOptVerified && !user.verified)
                throw new UnauthorizedException('Account not verified');

            if (
                user.lastRevoke &&
                payload.iat <= user.lastRevoke.getTime() / 1000
            )
                throw new UnauthorizedException();

            request['user'] = {
                id: user.id,
                username: user.username,
                email: user.email,
                verified: user.verified,
            };

            request['auth'] = {
                appId: payload.app,
                scope: payload.scp,
            };
        } catch {
            throw new UnauthorizedException();
        }
        return true;
    }

    private extractTokenFromHeader(request: Request): string | undefined {
        const [type, token] = request.headers.authorization?.split(' ') ?? [];
        return type === 'Bearer' ? token : undefined;
    }
}
