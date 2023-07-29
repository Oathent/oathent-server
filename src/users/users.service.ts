import { Injectable, ForbiddenException } from '@nestjs/common';
import * as argon2 from 'argon2';

import { PrismaClient, User } from '@prisma/client';
import { createSnowflake } from 'src/common';
import { jwtConstants } from 'src/auth/constants';
import { Token } from 'src/auth/auth.guard';
import { sendResetEmail, sendVerifyEmail } from 'src/email';
import { JwtService } from '@nestjs/jwt';
const prisma = new PrismaClient();

@Injectable()
export class UsersService {
    constructor(private readonly jwtService: JwtService) { }

    async findOneId(id: bigint): Promise<User | undefined> {
        const user = await prisma.user.findUnique({ where: { id } });
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

    async findOneUsername(username: string): Promise<User | undefined> {
        const user = await prisma.user.findUnique({ where: { username } });
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

        const verifyCodePayload = {
            typ: Token.VERIFY_CODE,
            sub: user.id,
        };

        const code = await this.jwtService.signAsync(verifyCodePayload, {
            expiresIn: jwtConstants.verifyCodeExpiry,
            secret: jwtConstants.verifyCodeSecret,
        });
        sendVerifyEmail(user, code);

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
        if (!await this.existsEmail(email))
            return;

        let user = await this.findOneEmail(email);

        const resetCodePayload = {
            typ: Token.PASSWORD_RESET_CODE,
            sub: user.id,
        };

        const code = await this.jwtService.signAsync(resetCodePayload, {
            expiresIn: jwtConstants.resetCodeExpiry,
            secret: jwtConstants.resetCodeSecret,
        });
        console.log(code);
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

            return { statusCode: 200, message: "Password successfully reset. You have been logged out of all sessions." };
        } catch (e) {
            console.log(e);
            throw new ForbiddenException('Password reset failed');
        }
    }
}
