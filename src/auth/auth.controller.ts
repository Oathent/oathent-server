import {
    Request,
    Body,
    Controller,
    Post,
    HttpCode,
    HttpStatus,
    Get,
    Query,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Token, UseAuth } from './auth.guard';
import { UsersService } from 'src/users/users.service';
import { AuthResponse, AuthRefreshResponse } from '../entities/auth.entity';
import {
    ApiTags,
    ApiOperation,
    ApiConflictResponse,
    ApiBadRequestResponse,
    ApiOkResponse,
    ApiForbiddenResponse,
    ApiExcludeEndpoint,
} from '@nestjs/swagger';
import {
    LoginDto,
    RegisterDto,
    RequestResetPasswordDto,
    ResetPasswordDto,
} from 'src/dto/auth.dto';
import { RateLimit, RateLimitEnv } from 'src/ratelimit.guard';
import { readFile } from 'fs/promises';

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
    @RateLimit(RateLimitEnv('auth/login', 10))
    @Post('login')
    signIn(@Body() loginDto: LoginDto) {
        return this.authService.signIn(loginDto.username, loginDto.password);
    }

    @ApiOperation({ summary: 'Register to to create a new account' })
    @ApiOkResponse({ description: 'Account tokens', type: AuthResponse })
    @ApiBadRequestResponse({ description: 'Bad request' })
    @ApiConflictResponse({ description: 'Conflict' })
    @HttpCode(HttpStatus.OK)
    @RateLimit(RateLimitEnv('auth/register', 10))
    @Post('register')
    createAccount(@Body() registerDto: RegisterDto) {
        return this.authService.createAccount(
            registerDto.username,
            registerDto.email,
            registerDto.password,
        );
    }

    @ApiOperation({ summary: 'Refresh account access token' })
    @ApiOkResponse({ description: 'Access token', type: AuthRefreshResponse })
    @RateLimit(RateLimitEnv('auth/refresh', 5))
    @UseAuth(Token.REFRESH, { account: true })
    @Post('refresh')
    refreshToken(@Request() req) {
        return this.authService.refreshToken(req.user.id);
    }

    @ApiOperation({
        summary: 'Revokes all access and refresh tokens for the account',
    })
    @ApiOkResponse({ description: 'Success' })
    @RateLimit(RateLimitEnv('auth/revoke', 5))
    @UseAuth(Token.ACCESS, { account: true })
    @Post('revoke')
    revokeTokens(@Request() req) {
        return this.usersService.revokeTokens(req.user.id);
    }

    @ApiOperation({ summary: 'Verifies an account using a verification token' })
    @ApiOkResponse({ description: 'Success' })
    @ApiForbiddenResponse({ description: 'Forbidden' })
    @RateLimit(RateLimitEnv('auth/verify', 5))
    @Get('verify')
    verifyAccount(@Query('code') code: string) {
        return this.usersService.verifyAccount(code);
    }

    @ApiOperation({
        summary: "Requests a password reset link be sent to the user's email",
    })
    @ApiOkResponse({
        description:
            "Success (Or account doesn't exist with that email. Prevents leaking data)",
    })
    @HttpCode(HttpStatus.OK)
    @RateLimit(RateLimitEnv('auth/requestreset', 5))
    @Post('requestreset')
    async requestResetPassword(
        @Body() requestResetPasswordDto: RequestResetPasswordDto,
    ) {
        return this.usersService.requestResetPassword(
            requestResetPasswordDto.email,
        );
    }

    @ApiExcludeEndpoint()
    @Get('reset')
    getResetPage() {
        return readFile('./public/reset.html', 'utf-8');
    }

    @ApiOperation({ summary: 'Resets the password for an account using the password reset token' })
    @ApiOkResponse({ description: 'Success' })
    @ApiForbiddenResponse({ description: 'Forbidden' })
    @RateLimit(RateLimitEnv('auth/reset', 5))
    @UseAuth(Token.PASSWORD_RESET_CODE)
    @Post('reset')
    resetPassword(@Request() req, @Body() resetPasswordDto: ResetPasswordDto) {
        return this.usersService.resetAccount(
            req.user.id,
            resetPasswordDto.password,
        );
    }
}
