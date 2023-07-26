
import { Injectable, UnauthorizedException, BadRequestException, ConflictException } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import * as argon2 from 'argon2';
import { JwtService } from '@nestjs/jwt';
import { jwtConstants } from './constants';
import { OauthService } from 'src/oauth/oauth.service';

@Injectable()
export class AuthService {
    constructor(
        private usersService: UsersService,
        private oauthService: OauthService,
        private jwtService: JwtService,
    ) { }

    async signIn(username: string, pass: string): Promise<any> {
        if (!username || !await this.usersService.existsUsername(username))
            throw new UnauthorizedException();

        const user = await this.usersService.findOneUsername(username);
        if (!user?.passHash || !await argon2.verify(user?.passHash, pass))
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

        let accessToken = await this.jwtService.signAsync(accessPayload, { expiresIn: jwtConstants.accessExpiry });
        // let refreshToken = await this.usersService.createRefreshToken(user.id, await this.jwtService.signAsync(refreshPayload, { secret: jwtConstants.refreshSecret, expiresIn: jwtConstants.refreshExpiry }));
        let refreshToken = await this.jwtService.signAsync(refreshPayload, { secret: jwtConstants.refreshSecret, expiresIn: jwtConstants.refreshExpiry });

        return {
            accessToken,
            refreshToken,
        };
    }

    async createAccount(username: string, email: string, pass: string) {
        if (!username || username.length < 4 || !username.match(process.env.USERNAME_REGEX ? new RegExp(process.env.USERNAME_REGEX, 'gi') : /^[A-Z0-9 ]+$/gi))
            throw new BadRequestException("Invalid username");

        if (!email.match(/^.+@.+\.[^@]+$/))
            throw new BadRequestException("Invalid email");

        if (!pass || pass.length < 8)
            throw new BadRequestException("Invalid password");

        if (await this.usersService.existsEmail(email) || await this.usersService.existsUsername(username))
            throw new ConflictException("User already exists with that username or email");

        await this.usersService.create(email, username, pass);
        return this.signIn(username, pass);
    }

    async refreshToken(id: bigint): Promise<any> {
        if (!await this.usersService.existsId(id))
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
            accessToken: await this.jwtService.signAsync(accessPayload, { expiresIn: jwtConstants.accessExpiry }),
        };
    }
}
