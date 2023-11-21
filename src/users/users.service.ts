import {
    Injectable,
    ForbiddenException,
    UnauthorizedException,
} from '@nestjs/common';
import * as argon2 from 'argon2';

import {
    PrismaClient,
    SocialLogin,
    SocialProvider,
    User,
} from '@prisma/client';
import { createSnowflake } from 'src/common';
import { jwtConstants } from 'src/auth/constants';
import { Token } from 'src/auth/auth.guard';
import { sendResetEmail, sendVerifyEmail } from 'src/email';
import { JwtService } from '@nestjs/jwt';
import { genTotpSecret } from 'src/mfa';
const prisma = new PrismaClient();

@Injectable()
export class UsersService {
    constructor(private readonly jwtService: JwtService) { }

    async findOneId(
        id: bigint,
        includeSocial?: boolean,
        includeMFA?: boolean,
    ): Promise<User | undefined | any> {
        const socialLogins = includeSocial
            ? {
                select: {
                    provider: includeSocial,
                    providerId: includeSocial,
                    socialName: includeSocial,
                },
            }
            : false;
        const mfaMethods = includeMFA
            ? {
                select: {
                    method: includeMFA,
                    secret: includeMFA,
                },
            }
            : false;

        const user = await prisma.user.findUnique({
            where: { id },
            include: { socialLogins, mfaMethods },
        });
        if (!user) {
            throw new Error("Account doesn't exist");
        }

        return user;
    }

    async findOneEmail(email: string): Promise<User | undefined> {
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
            throw new Error("Account doesn't exist");
        }

        return user;
    }

    async findOneUsername(
        username: string,
        includeSocial?: boolean,
        includeMFA?: boolean,
    ): Promise<User | undefined | any> {
        const socialLogins = includeSocial
            ? {
                select: {
                    provider: includeSocial,
                    providerId: includeSocial,
                    socialName: includeSocial,
                },
            }
            : false;
        const mfaMethods = includeMFA
            ? {
                select: {
                    method: includeMFA,
                    secret: includeMFA,
                },
            }
            : false;

        const user = await prisma.user.findUnique({
            where: { username },
            include: { socialLogins, mfaMethods },
        });
        if (!user) {
            throw new Error("Account doesn't exist");
        }

        return user;
    }

    async findOneSocialLogin(
        provider: SocialProvider,
        providerId: string,
    ): Promise<User | undefined> {
        const user = await prisma.user.findFirst({
            where: { socialLogins: { some: { provider, providerId } } },
        });
        if (!user) {
            throw new Error("Account doesn't exist");
        }

        return user;
    }

    async existsId(id: bigint): Promise<boolean> {
        const user = await prisma.user.findUnique({ where: { id } });
        return !!user;
    }

    async existsEmail(email: string): Promise<boolean> {
        const user = await prisma.user.findUnique({ where: { email } });
        return !!user;
    }

    async existsUsername(username: string): Promise<boolean> {
        const user = await prisma.user.findUnique({ where: { username } });
        return !!user;
    }

    async existsSocialLogin(
        provider: SocialProvider,
        providerId: string,
    ): Promise<boolean> {
        const user = await prisma.user.findFirst({
            where: { socialLogins: { some: { provider, providerId } } },
        });
        return !!user;
    }

    async create(
        email: string,
        username: string,
        password: string,
    ): Promise<User | undefined> {
        const passHash = await argon2.hash(password);

        const user = await prisma.user.create({
            data: {
                id: createSnowflake(),
                email,
                username,
                passHash,
                verified:
                    process.env.DISABLE_VERIFICATION &&
                    process.env.DISABLE_VERIFICATION == 'yes',
            },
        });

        if (
            !process.env.DISABLE_VERIFICATION ||
            process.env.DISABLE_VERIFICATION != 'yes'
        ) {
            const verifyCodePayload = {
                typ: Token.VERIFY_CODE,
                sub: user.id,
            };

            const code = await this.jwtService.signAsync(verifyCodePayload, {
                expiresIn: jwtConstants.verifyCodeExpiry,
                secret: jwtConstants.verifyCodeSecret,
            });
            sendVerifyEmail(user, code);
        }

        return user;
    }

    async revokeTokens(id: bigint): Promise<any> {
        await prisma.user.update({
            where: {
                id,
            },
            data: {
                lastRevoke: new Date(),
            },
        });
    }

    async verifyAccount(code: string): Promise<any> {
        try {
            const payload = await this.jwtService.verifyAsync(code, {
                secret: jwtConstants.verifyCodeSecret,
            });

            if (payload.typ != Token.VERIFY_CODE) throw null;

            await prisma.user.update({
                where: {
                    id: payload.sub,
                },
                data: {
                    verified: true,
                },
            });

            return 'Account verified';
        } catch (e) {
            throw new ForbiddenException(
                'Verification failed (Perhaps the code was invalid or expired)',
            );
        }
    }

    async requestResetPassword(email: string) {
        if (!(await this.existsEmail(email))) return;

        const user = await this.findOneEmail(email);

        const resetCodePayload = {
            typ: Token.PASSWORD_RESET_CODE,
            sub: user.id,
        };

        const code = await this.jwtService.signAsync(resetCodePayload, {
            expiresIn: jwtConstants.resetCodeExpiry,
            secret: jwtConstants.resetCodeSecret,
        });
        sendResetEmail(user, code);
    }

    async resetAccount(userId: bigint, password: string): Promise<any> {
        try {
            const passHash = await argon2.hash(password);

            await prisma.user.update({
                where: {
                    id: userId,
                },
                data: {
                    passHash,
                    lastRevoke: new Date(),
                },
            });

            return {
                statusCode: 200,
                message:
                    'Password successfully reset. You have been logged out of all sessions.',
            };
        } catch (e) {
            throw new ForbiddenException('Password reset failed');
        }
    }

    async deleteAccount(userId: bigint): Promise<any> {
        await prisma.user.delete({
            where: {
                id: userId,
            },
        });

        return {
            sucess: true,
        };
    }

    async createSocial(
        email: string,
        username: string,
        provider: SocialProvider,
        providerId: string,
        socialName?: string,
        password?: string,
    ): Promise<User | undefined> {
        const passHash = password ? await argon2.hash(password) : undefined;

        const user = await prisma.user.create({
            data: {
                id: createSnowflake(),
                email,
                username,
                socialLogins: {
                    create: {
                        provider,
                        providerId,
                        socialName,
                    },
                },
                passHash,
                verified:
                    process.env.DISABLE_VERIFICATION &&
                    process.env.DISABLE_VERIFICATION == 'yes',
            },
        });

        if (
            !process.env.DISABLE_VERIFICATION ||
            process.env.DISABLE_VERIFICATION != 'yes'
        ) {
            const verifyCodePayload = {
                typ: Token.VERIFY_CODE,
                sub: user.id,
            };

            const code = await this.jwtService.signAsync(verifyCodePayload, {
                expiresIn: jwtConstants.verifyCodeExpiry,
                secret: jwtConstants.verifyCodeSecret,
            });
            sendVerifyEmail(user, code);
        }

        return user;
    }

    async linkSocial(
        userId: bigint,
        provider: SocialProvider,
        providerId: string,
        socialName?: string,
    ): Promise<SocialLogin> {
        const social = await prisma.socialLogin.create({
            data: {
                userId,
                provider,
                providerId,
                socialName,
            },
        });

        return social;
    }

    async unlinkSocial(
        userId: bigint,
        provider: SocialProvider,
    ): Promise<void> {
        await prisma.socialLogin.delete({
            where: {
                userId_provider: {
                    userId,
                    provider,
                },
            },
        });
    }

    async changePassword(
        userId: bigint,
        newPassword: string,
        oldPassword?: string,
    ): Promise<any> {
        const user = await this.findOneId(userId);
        if (
            !user ||
            (user?.passHash &&
                !(await argon2.verify(user?.passHash, oldPassword)))
        )
            throw new UnauthorizedException();

        if (newPassword == oldPassword)
            throw new UnauthorizedException(
                'New password and old password cannot match',
            );

        try {
            const passHash = await argon2.hash(newPassword);

            await prisma.user.update({
                where: {
                    id: userId,
                },
                data: {
                    passHash,
                    lastRevoke: new Date(),
                },
            });

            return {
                statusCode: 200,
                success: true,
                message:
                    'Password successfully changed. You have been logged out of all sessions',
            };
        } catch (e) {
            console.log(e);
            throw new ForbiddenException('Password change failed');
        }
    }

    async addTotp(
        userId: bigint,
    ): Promise<any> {
        const user = await this.findOneId(userId);
        if (!user)
            return new ForbiddenException();

        const secret = genTotpSecret();

        try {
            await prisma.mFADetail.create({
                data: {
                    userId: user.id,
                    method: 'TOTP',
                    secret,
                }
            });
        } catch (e) {
            return {
                success: false,
                msg: "Couldn't setup one-time password",
            }
        }

        return {
            success: true,
            secret,
        }
    }
}
