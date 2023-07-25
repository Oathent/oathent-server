import {
    CanActivate,
    ExecutionContext,
    Injectable,
    UnauthorizedException,
    UseGuards,
    SetMetadata,
    applyDecorators,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Scopes, jwtConstants } from './constants';
import { Request } from 'express';
import { UsersService } from 'src/users/users.service';
import { Reflector } from '@nestjs/core';
import { OauthService } from 'src/oauth/oauth.service';

export const AUTH_KEY_TYPE = 'authKeyType';
export const AUTH_SCOPES = 'authScopes';

export enum Token {
    ACCESS = 'a',
    REFRESH = 'r',
    CODE = 'c',
    DEVICE_CODE = 'd',
};

export const UseAuth = (type?: Token, scopes?: Scopes[]) => {
    return applyDecorators(
        SetMetadata(AUTH_KEY_TYPE, type || Token.ACCESS),
        SetMetadata(AUTH_SCOPES, scopes || []),
        UseGuards(AuthGuard),
    );
};

@Injectable()
export class AuthGuard implements CanActivate {
    constructor(
        private jwtService: JwtService,
        private usersService: UsersService,
        private oauthService: OauthService,
        private reflector: Reflector,
    ) { }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        const token = this.extractTokenFromHeader(request);
        if (!token) {
            throw new UnauthorizedException();
        }
        try {
            const authKeyType = this.reflector.getAllAndOverride<Token>(AUTH_KEY_TYPE, [
                context.getHandler(),
                context.getClass(),
            ]);
            const authScopes = this.reflector.getAllAndOverride<Scopes[]>(AUTH_SCOPES, [
                context.getHandler(),
                context.getClass(),
            ]);

            let data = await this.jwtService.decode(token);
            if(typeof data == 'string')
                throw new UnauthorizedException();

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
                case Token.CODE:
                    request['oauthCode'] = {
                        userId: data.sub,
                        appId: data.app,
                        scope: data.scp,
                        allowRefresh: data.ref,
                    };
                    break;
            }

            if (data.app) {
                if (!await this.oauthService.hasAuthInfo(data.sub, data.app))
                    throw new UnauthorizedException();

                let authInfo = await this.oauthService.getAuthInfo(data.sub, data.app);
                secret = authInfo.jwtSecret;
            }

            const payload = await this.jwtService.verifyAsync(token, { secret });

            
            if(payload.typ != authKeyType || payload.app && authScopes.reduce((p: boolean, c: Scopes) => p && (payload.scp & c) !== c, false))
                throw new UnauthorizedException();
            
            if(authKeyType === Token.DEVICE_CODE) {
                request['deviceCode'] = token;
                return true;
            }
                
            if (!await this.usersService.existsId(payload.sub))
                throw new UnauthorizedException();
                
            let user = await this.usersService.findOneId(payload.sub);

            if (user.lastRevoke && payload.iat <= user.lastRevoke.getTime() / 1000)
                throw new UnauthorizedException();

            if (authKeyType == Token.REFRESH && !user.refreshTokens.includes(token))
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