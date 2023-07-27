import { BadRequestException, Injectable, UnauthorizedException, Inject, forwardRef } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Auth, PrismaClient } from '@prisma/client';
import { randomBytes } from 'crypto';
import { jwtConstants } from 'src/auth/constants';
import { createSnowflake, limitScopeToMax } from 'src/common';
import { UsersService } from 'src/users/users.service';
import { addDeviceCodeInfo, getDeviceCodeInfo, getDeviceCodeStatus, setDeviceCodeStatus } from './deviceCodes';
import { MAX_SCOPE, SCOPES, scopeValToName } from 'src/auth/scopes';

const prisma = new PrismaClient();

@Injectable()
export class OauthService {
    constructor(
        @Inject(forwardRef(() => UsersService))
        private usersService: UsersService,
        private jwtService: JwtService
    ) { }

    async authorizeApp(userId: bigint, appId: bigint, scope: number, flow: string, code?: string, redirect?: string): Promise<any> {
        if (!await this.usersService.existsId(userId))
            throw new UnauthorizedException();

        if (flow == 'auth_code') {
            return await this.generateAuthCode(userId, appId, scope, redirect);
        }
        if (flow == 'device_code' && code) {
            return await this.authorizeDeviceCode(userId, appId, scope, code);
        }

        throw new BadRequestException();
    }

    async rejectApp(userId: bigint, appId: bigint, scope: number, flow: string, code?: string): Promise<any> {
        if (!await this.usersService.existsId(userId))
            throw new UnauthorizedException();

        if (flow == 'auth_code') {
            return { success: true };
        }
        if (flow == 'device_code' && code) {
            return await this.rejectDeviceCode(userId, appId, scope, code);
        }

        throw new BadRequestException();
    }

    async generateAuthCode(userId: bigint, appId: bigint, scope: number, redirect: string) {
        const user = await this.usersService.findOneId(userId);
        const app = await this.getAppDetails(appId, true);

        if(!app.redirects.find(r => r.uri == redirect))
            throw new BadRequestException("Invalid redirect URI");

        const authInfo = await this.findOrCreateAuthInfo(userId, appId);

        const payload = {
            typ: 'c',
            sub: user.id,
            app: appId,
            scp: limitScopeToMax(scope),
        };

        return {
            success: true,
            code: await this.jwtService.signAsync(payload, { expiresIn: jwtConstants.authCodeExpiry, secret: authInfo.jwtSecret }),
        };
    }

    async isDeviceCodeValid(code: string): Promise<boolean> {
        try {
            if (await this.jwtService.verifyAsync(code, { secret: jwtConstants.deviceCodeSecret }))
                return true;
        } catch (e) {
            return false;
        }

        return false;
    }

    async authorizeDeviceCode(userId: bigint, appId: bigint, scope: number, code: string) {
        if (!await this.isDeviceCodeValid(code))
            throw new UnauthorizedException();

        await this.findOrCreateAuthInfo(userId, appId);

        let { exp } = await this.jwtService.verifyAsync(code, { secret: jwtConstants.deviceCodeSecret });
        addDeviceCodeInfo(code, 'authed', userId, appId, scope, exp);
        return { success: true };
    }

    async rejectDeviceCode(userId: bigint, appId: bigint, scope: number, code: string) {
        if (!await this.isDeviceCodeValid(code))
            throw new UnauthorizedException();

        let { exp } = await this.jwtService.verifyAsync(code, { secret: jwtConstants.deviceCodeSecret });
        addDeviceCodeInfo(code, 'rejected', userId, appId, scope, exp);
        return { success: true };
    }

    async createToken(userId: bigint, appId: bigint, scope: number): Promise<any> {
        if (!await this.hasAuthInfo(userId, appId))
            throw new UnauthorizedException();

        const user = await this.usersService.findOneId(userId);
        const authInfo = await this.getAuthInfo(userId, appId);

        const accessPayload = {
            typ: 'a',
            sub: user.id,
            usr: user.username,
            app: appId,
            scp: limitScopeToMax(scope),
        };

        const refreshPayload = {
            typ: 'r',
            sub: user.id,
            usr: user.username,
            app: appId,
            scp: limitScopeToMax(scope),
        };

        let accessToken = await this.jwtService.signAsync(accessPayload, { expiresIn: jwtConstants.accessExpiry, secret: authInfo.jwtSecret });
        let refreshToken = await this.jwtService.signAsync(refreshPayload, { expiresIn: jwtConstants.refreshExpiry, secret: authInfo.jwtSecret });

        return {
            accessToken,
            refreshToken,
        };
    }

    async hasAuthInfo(userId: bigint, appId: bigint): Promise<boolean> {
        let authInfo = await prisma.auth.findFirst({ where: { userId, appId } });
        return !!authInfo;
    }

    async createAuthInfo(userId: bigint, appId: bigint): Promise<Auth> {
        if (!await this.usersService.existsId(userId) || !await this.appExists(appId))
            throw new BadRequestException();

        let authInfo = await prisma.auth.create({
            data: {
                id: createSnowflake(),
                userId,
                appId,
                jwtSecret: randomBytes(32).toString('base64'),
            }
        });

        return authInfo;
    }

    async getAuthInfo(userId: bigint, appId: bigint): Promise<Auth | undefined> {
        let authInfo = await prisma.auth.findFirst({ where: { userId, appId } });
        if (!authInfo) {
            throw new Error("Auth info doesn't exist");
        }

        return authInfo;
    }

    async findOrCreateAuthInfo(userId: bigint, appId: bigint): Promise<Auth> {
        if (await this.hasAuthInfo(userId, appId))
            return this.getAuthInfo(userId, appId);
        else
            return this.createAuthInfo(userId, appId);
    }

    async revokeApp(userId: bigint, appId: bigint): Promise<any> {
        if (!await this.hasAuthInfo(userId, appId))
            throw new BadRequestException();

        let authInfo = await this.getAuthInfo(userId, appId);
        await prisma.auth.delete({ where: { id: authInfo.id } });
    }

    async appExists(id: bigint): Promise<boolean> {
        let application = await prisma.application.findUnique({ where: { id } });
        return !!application;
    }

    async getAppDetails(id: bigint, includeRedirects?: boolean): Promise<any> {
        try {
            let app = await prisma.application.findFirst({ where: { id }, include: { redirects: includeRedirects } });
            if (!app) {
                throw new BadRequestException("Application doesn't exist");
            }

            let useCount = await prisma.auth.count({ where: { appId: app.id } });

            return {
                id: app.id,
                name: app.name,
                avatarPath: app.avatarUrl,
                bypassScopes: app.bypassScopes,
                useCount,
                redirects: app.redirects,
            };
        } catch(e) {
            throw new BadRequestException("Application doesn't exist");
        }
    }

    async getScopeStrings(scope: number): Promise<any> {
        let scopeStrs = [scopeValToName(0)];

        const numBits = Math.ceil(Math.log2(scope & MAX_SCOPE));

        for (var mask = 1 << numBits; mask; mask >>= 1) {
            let bit = scope & mask;
            if (bit && scopeValToName(bit))
                scopeStrs.push(scopeValToName(bit));
        }

        return scopeStrs.sort((a, b) => SCOPES[a] - SCOPES[b]);
    }

    async createDeviceCode(ip: string, seed: string): Promise<any> {
        const MIN_SEED_LEN = 16;
        if (!seed)
            throw new BadRequestException(`Seed value missing`)
        if (seed.length < MIN_SEED_LEN)
            throw new BadRequestException(`Seed was less than ${MIN_SEED_LEN}`)

        const codePayload = {
            typ: 'd',
            sub: ip,
            see: seed.substring(0, 16),
        };

        let code = await this.jwtService.signAsync(codePayload, { expiresIn: jwtConstants.deviceCodeExpiry, secret: jwtConstants.deviceCodeSecret });
        return { code };
    }

    async redeemDeviceCodeToken(code: string): Promise<any> {
        if (!await this.isDeviceCodeValid(code))
            throw new UnauthorizedException();

        setDeviceCodeStatus(code, 'redeemed');
        let { userId, appId, scope } = getDeviceCodeInfo(code);
        return await this.createToken(userId, appId, scope)
    }

    async refreshToken(userId: bigint, appId: bigint, scope: number): Promise<any> {
        if (!await this.usersService.existsId(userId))
            throw new UnauthorizedException();

        if (!await this.hasAuthInfo(userId, appId))
            return { success: false };

        let authInfo = await this.getAuthInfo(userId, appId);

        const user = await this.usersService.findOneId(userId);

        const accessPayload = {
            typ: 'a',
            sub: user.id,
            usr: user.username,
            app: appId,
            scp: limitScopeToMax(scope),
        };

        let accessToken = await this.jwtService.signAsync(accessPayload, { expiresIn: jwtConstants.accessExpiry, secret: authInfo.jwtSecret });

        return {
            success: true,
            accessToken,
        };
    }
}