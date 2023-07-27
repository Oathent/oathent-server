import { Request, Body, Controller, Post, HttpCode, HttpStatus, Get, Query } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Token, UseAuth } from './auth.guard';
import { UsersService } from 'src/users/users.service';
import { AuthResponse, AuthRefreshResponse } from '../entities/auth.entity'
import { ApiTags, ApiOperation, ApiConflictResponse, ApiBadRequestResponse, ApiOkResponse, ApiForbiddenResponse } from '@nestjs/swagger';
import { LoginDto, RegisterDto } from 'src/dto/auth.dto';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
    constructor(
        private authService: AuthService,
        private usersService: UsersService,
    ) { }

    @ApiOperation({ summary: 'Login to an existing account' })
    @ApiOkResponse({ description: 'Account tokens', type: AuthResponse })
    @HttpCode(HttpStatus.OK)
    @Post('login')
    signIn(@Body() loginDto: LoginDto) {
        return this.authService.signIn(loginDto.username, loginDto.password);
    }

    @ApiOperation({ summary: 'Register to to create a new account' })
    @ApiOkResponse({ description: 'Account tokens', type: AuthResponse })
    @ApiBadRequestResponse({ description: 'Bad request' })
    @ApiConflictResponse({ description: 'Conflict' })
    @HttpCode(HttpStatus.OK)
    @Post('register')
    createAccount(@Body() registerDto: RegisterDto) {
        return this.authService.createAccount(registerDto.username, registerDto.email, registerDto.password);
    }

    @ApiOperation({ summary: 'Refresh account access token' })
    @ApiOkResponse({ description: 'Access token', type: AuthRefreshResponse })
    @UseAuth(Token.REFRESH, { account: true })
    @Post('refresh')
    refreshToken(@Request() req) {
        return this.authService.refreshToken(req.user.id);
    }

    @ApiOperation({ summary: 'Revokes all access and refresh tokens for the account' })
    @ApiOkResponse({ description: 'Success' })
    @UseAuth(Token.ACCESS, { account: true })
    @Post('revoke')
    revokeTokens(@Request() req) {
        return this.usersService.revokeTokens(req.user.id);
    }

    @ApiOperation({ summary: 'Verifies an account using a verification token' })
    @ApiOkResponse({ description: 'Success' })
    @ApiForbiddenResponse({ description: 'Forbidden' })
    @Get('verify')
    verifyAccount(@Query('code') code: string) {
        return this.usersService.verifyAccount(code);
    }
}
