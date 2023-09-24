import {
    Injectable,
    UnauthorizedException,
    BadRequestException,
    ConflictException,
    UnprocessableEntityException,
} from '@nestjs/common';
import { UsersService } from '../users/users.service';
import * as argon2 from 'argon2';
import { JwtService } from '@nestjs/jwt';
import { jwtConstants } from './constants';
import { verifyDiscordOAuth, verifyGoogleToken } from 'src/social';
import { SocialProvider } from '@prisma/client';

@Injectable()
export class AuthService {
    constructor(
        private usersService: UsersService,
        private jwtService: JwtService,
    ) {}

    async signIn(username: string, pass: string): Promise<any> {
        if (!username || !(await this.usersService.existsUsername(username)))
            throw new UnauthorizedException();

        const user = await this.usersService.findOneUsername(username);
        if (!user?.passHash || !(await argon2.verify(user?.passHash, pass)))
            throw new UnauthorizedException();

        const accessPayload = {
            typ: 'a',
            sub: user.id,
            usr: user.username,
            app: null,
            scp: null,
        };

        const refreshPayload = {
            typ: 'r',
            sub: user.id,
            usr: user.username,
            app: null,
            scp: null,
        };

        const accessToken = await this.jwtService.signAsync(accessPayload, {
            expiresIn: jwtConstants.accessExpiry,
        });
        // let refreshToken = await this.usersService.createRefreshToken(user.id, await this.jwtService.signAsync(refreshPayload, { secret: jwtConstants.refreshSecret, expiresIn: jwtConstants.refreshExpiry }));
        const refreshToken = await this.jwtService.signAsync(refreshPayload, {
            secret: jwtConstants.refreshSecret,
            expiresIn: jwtConstants.refreshExpiry,
        });

        return {
            accessToken,
            refreshToken,
        };
    }

    async createAccount(username: string, email: string, pass: string) {
        if (
            !username ||
            username.length <
                (process.env.USERNAME_MIN_LENGTH &&
                !isNaN(Number(process.env.USERNAME_MIN_LENGTH))
                    ? Number(process.env.USERNAME_MIN_LENGTH)
                    : 4) ||
            !username.match(
                process.env.USERNAME_REGEX
                    ? new RegExp(process.env.USERNAME_REGEX, 'gi')
                    : /^[A-Z0-9 ]+$/gi,
            ) ||
            username.length >
                (process.env.USERNAME_MAX_LENGTH &&
                !isNaN(Number(process.env.USERNAME_MAX_LENGTH))
                    ? Number(process.env.USERNAME_MAX_LENGTH)
                    : 32)
        )
            throw new BadRequestException('Invalid username');

        if (!email.match(/^.+@.+\.[^@]+$/))
            throw new BadRequestException('Invalid email');

        if (!pass || pass.length < 8)
            throw new BadRequestException('Invalid password');

        if (
            (await this.usersService.existsEmail(email)) ||
            (await this.usersService.existsUsername(username))
        )
            throw new ConflictException(
                'User already exists with that username or email',
            );

        await this.usersService.create(email, username, pass);
        return this.signIn(username, pass);
    }

    async refreshToken(id: bigint): Promise<any> {
        if (!(await this.usersService.existsId(id)))
            throw new UnauthorizedException();

        const user = await this.usersService.findOneId(id);

        const accessPayload = {
            typ: 'a',
            sub: user.id,
            usr: user.username,
            app: null,
            scp: null,
        };

        return {
            accessToken: await this.jwtService.signAsync(accessPayload, {
                expiresIn: jwtConstants.accessExpiry,
            }),
        };
    }

    async handleSocialLogin(provider: string, auth: string): Promise<any> {
        let authed = false;
        let providerId;
        let providerVal: SocialProvider;
        switch (provider) {
            case 'google': {
                const { success, userId } = await verifyGoogleToken(auth);
                authed = success;
                providerId = userId;
                providerVal = SocialProvider.GOOGLE;
                break;
            }
            case 'discord': {
                const { success, userId } = await verifyDiscordOAuth(auth);
                authed = success;
                providerId = userId;
                providerVal = SocialProvider.DISCORD;
                break;
            }
            default:
                throw new UnauthorizedException();
        }

        if (!authed || !providerId) throw new UnauthorizedException();

        if (
            !(await this.usersService.existsSocialLogin(
                providerVal,
                providerId,
            ))
        )
            throw new UnprocessableEntityException('Not linked to an account');

        const user = await this.usersService.findOneSocialLogin(
            providerVal,
            providerId,
        );

        const accessPayload = {
            typ: 'a',
            sub: user.id,
            usr: user.username,
            app: null,
            scp: null,
        };

        const refreshPayload = {
            typ: 'r',
            sub: user.id,
            usr: user.username,
            app: null,
            scp: null,
        };

        const accessToken = await this.jwtService.signAsync(accessPayload, {
            expiresIn: jwtConstants.accessExpiry,
        });
        const refreshToken = await this.jwtService.signAsync(refreshPayload, {
            secret: jwtConstants.refreshSecret,
            expiresIn: jwtConstants.refreshExpiry,
        });

        return {
            accessToken,
            refreshToken,
        };
    }

    async handleSocialRegister(
        provider: string,
        auth: string,
        username: string,
        pass: string,
    ): Promise<any> {
        if (
            !username ||
            username.length <
                (process.env.USERNAME_MIN_LENGTH &&
                !isNaN(Number(process.env.USERNAME_MIN_LENGTH))
                    ? Number(process.env.USERNAME_MIN_LENGTH)
                    : 4) ||
            !username.match(
                process.env.USERNAME_REGEX
                    ? new RegExp(process.env.USERNAME_REGEX, 'gi')
                    : /^[A-Z0-9 ]+$/gi,
            ) ||
            username.length >
                (process.env.USERNAME_MAX_LENGTH &&
                !isNaN(Number(process.env.USERNAME_MAX_LENGTH))
                    ? Number(process.env.USERNAME_MAX_LENGTH)
                    : 32)
        )
            throw new BadRequestException('Invalid username');

        if (pass && pass.length < 8)
            throw new BadRequestException('Invalid password');

        let authed = false;
        let providerId: string, email: string, socialName: string | undefined;
        let providerVal: SocialProvider;
        switch (provider) {
            case 'google': {
                const { success, userId, userEmail, userGivenName } =
                    await verifyGoogleToken(auth);
                authed = success;
                providerId = userId;
                email = userEmail;
                socialName = userGivenName;
                providerVal = SocialProvider.GOOGLE;
                break;
            }
            case 'discord': {
                const { success, userId, username, userEmail } =
                    await verifyDiscordOAuth(auth);
                authed = success;
                providerId = userId;
                email = userEmail;
                socialName = username;
                providerVal = SocialProvider.DISCORD;
                break;
            }
            default:
                throw new UnauthorizedException();
        }

        if (!authed || !providerId) throw new UnauthorizedException();

        if (!email.match(/^.+@.+\.[^@]+$/))
            throw new BadRequestException('Invalid email');

        if (
            (await this.usersService.existsEmail(email)) ||
            (await this.usersService.existsUsername(username))
        )
            throw new ConflictException(
                'User already exists with that username or email',
            );

        await this.usersService.createSocial(
            email,
            username,
            providerVal,
            providerId,
            socialName,
            pass,
        );
        return this.handleSocialLogin(provider, auth);
    }
    async handleSocialLink(
        id: bigint,
        provider: string,
        auth: string,
    ): Promise<any> {
        let authed = false;
        let providerId, socialName;
        let providerVal: SocialProvider;
        switch (provider.toLowerCase()) {
            case 'google': {
                const { success, userId, userGivenName } =
                    await verifyGoogleToken(auth);
                authed = success;
                providerId = userId;
                socialName = userGivenName;
                providerVal = SocialProvider.GOOGLE;
                break;
            }
            case 'discord': {
                const { success, userId, username } = await verifyDiscordOAuth(
                    auth,
                );
                authed = success;
                providerId = userId;
                socialName = username;
                providerVal = SocialProvider.DISCORD;
                break;
            }
            default:
                throw new UnauthorizedException();
        }

        if (!authed || !providerId) throw new UnauthorizedException();

        try {
            await this.usersService.linkSocial(
                id,
                providerVal,
                providerId,
                socialName,
            );
            return { success: true };
        } catch (e) {
            return { success: false };
        }
    }
    async handleSocialUnlink(id: bigint, provider: string): Promise<any> {
        let providerVal: SocialProvider;
        switch (provider.toLowerCase()) {
            case 'google':
                providerVal = SocialProvider.GOOGLE;
                break;
            case 'discord':
                providerVal = SocialProvider.DISCORD;
                break;
            default:
                throw new UnauthorizedException();
        }

        try {
            await this.usersService.unlinkSocial(id, providerVal);

            const user = await this.usersService.findOneId(id, true);
            if (user.socialLogins.length == 0 && user.passHash == null) {
                await this.usersService.deleteAccount(id);
            }

            return { success: true };
        } catch (e) {
            return { success: false };
        }
    }

    async handleDeleteAccount(id: bigint): Promise<any> {
        try {
            await this.usersService.deleteAccount(id);
            return { success: true };
        } catch (e) {
            return { success: false };
        }
    }
}
