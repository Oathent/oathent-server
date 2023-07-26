import { Injectable } from '@nestjs/common';
import * as argon2 from 'argon2';

import { PrismaClient, User } from '@prisma/client';
import { createSnowflake } from 'src/common';
const prisma = new PrismaClient();

@Injectable()
export class UsersService {
    async findOneId(id: bigint): Promise<User | undefined> {
        let user = await prisma.user.findUnique({ where: { id } });
        if (!user) {
            throw new Error("Account doesn't exist");
        }

        return user;
    }

    async findOneEmail(email: string): Promise<User | undefined> {
        let user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
            throw new Error("Account doesn't exist");
        }

        return user;
    }

    async findOneUsername(username: string): Promise<User | undefined> {
        let user = await prisma.user.findUnique({ where: { username } });
        if (!user) {
            throw new Error("Account doesn't exist");
        }

        return user;
    }

    async existsId(id: bigint): Promise<boolean> {
        let user = await prisma.user.findUnique({ where: { id } });
        return !!user;
    }

    async existsEmail(email: string): Promise<boolean> {
        let user = await prisma.user.findUnique({ where: { email } });
        return !!user;
    }

    async existsUsername(username: string): Promise<boolean> {
        let user = await prisma.user.findUnique({ where: { username } });
        return !!user;
    }

    async create(email: string, username: string, password: string): Promise<User | undefined> {
        let passHash = await argon2.hash(password);

        let user = await prisma.user.create({
            data: {
                id: createSnowflake(),
                email,
                username,
                passHash,
            }
        });

        return user;
    }

    // async createRefreshToken(id: bigint, token: string): Promise<String | undefined> {
    //     const user = await prisma.user.findUnique({ where: { id } })

    //     user.refreshTokens.push(token)

    //     await prisma.user.update({
    //         where: {
    //             id,
    //         },
    //         data: {
    //             refreshTokens: user.refreshTokens,
    //         }
    //     });

    //     return token;
    // }

    async revokeTokens(id: bigint): Promise<any> {
        await prisma.user.update({
            where: {
                id,
            },
            data: {
                refreshTokens: [],
                lastRevoke: new Date(),
            }
        });
    }
}