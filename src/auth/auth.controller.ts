import { Request, Body, Controller, Post, HttpCode, HttpStatus, Get, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Token, UseAuth } from './auth.guard';
import { UsersService } from 'src/users/users.service';
import { Scopes } from './constants';

@Controller('auth')
export class AuthController {
    constructor(
        private authService: AuthService,
        private usersService: UsersService,
    ) { }

    @HttpCode(HttpStatus.OK)
    @Post('login')
    signIn(@Body() signInDto: Record<string, any>) {
        return this.authService.signIn(signInDto.username, signInDto.password);
    }

    @HttpCode(HttpStatus.OK)
    @Post('register')
    createAccount(@Body() registerDto: Record<string, any>) {
        return this.authService.createAccount(registerDto.username, registerDto.email, registerDto.password);
    }

    @UseAuth(Token.ACCESS, [Scopes.EMAIL])
    @Get('profile')
    getProfile(@Request() req) {
        return req.user;
    }

    @UseAuth(Token.REFRESH)
    @Post('refresh')
    refreshToken(@Request() req) {
        if (req.auth.app)
            throw new UnauthorizedException();

        return this.authService.refreshToken(req.user.id);
    }

    @UseAuth()
    @Post('revoke')
    revokeTokens(@Request() req) {
        return this.usersService.revokeTokens(req.user.id);
    }
}
