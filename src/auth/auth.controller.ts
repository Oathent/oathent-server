import {
    Request,
    Body,
    Controller,
    Post,
    HttpCode,
    HttpStatus,
    Get,
    Query,
    Param,
    Res,
    Patch,
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
    ApiUnprocessableEntityResponse,
} from '@nestjs/swagger';
import {
    ChangePasswordDto,
    LoginDto,
    RegisterDto,
    RequestResetPasswordDto,
    ResetPasswordDto,
    SocialLoginDto,
    SocialRegisterDto,
    SocialUnlinkDto,
} from 'src/dto/auth.dto';
import { RateLimit, RateLimitEnv } from 'src/ratelimit.guard';
import { readFile } from 'fs/promises';
import { protocolPorts } from 'src/email';
import { redeemDiscordOAuthCode, redeemGitHubOAuthCode } from 'src/social';

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
    @RateLimit(RateLimitEnv('auth/login', 5))
    @Post('login')
    signIn(@Body() loginDto: LoginDto) {
        return this.authService.signIn(loginDto.username, loginDto.password);
    }

    @ApiOperation({ summary: 'Register to to create a new account' })
    @ApiOkResponse({ description: 'Account tokens', type: AuthResponse })
    @ApiBadRequestResponse({ description: 'Bad request' })
    @ApiConflictResponse({ description: 'Conflict' })
    @HttpCode(HttpStatus.OK)
    @RateLimit(RateLimitEnv('auth/register', 5))
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

    @ApiOperation({
        summary:
            'Resets the password for an account using the password reset token',
    })
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

    @ApiOperation({ summary: 'Log in with a social account' })
    @ApiOkResponse({ description: 'Account tokens', type: AuthResponse })
    @ApiForbiddenResponse({ description: 'Forbidden' })
    @ApiUnprocessableEntityResponse({
        description: 'No account is linked to the login',
    })
    @RateLimit(RateLimitEnv('auth/social/login', 5))
    @Post('social/login')
    socialLogin(@Body() socialLoginDto: SocialLoginDto) {
        return this.authService.handleSocialLogin(
            socialLoginDto.provider,
            socialLoginDto.auth,
        );
    }

    @ApiOperation({ summary: 'Register with a social account' })
    @ApiOkResponse({ description: 'Account tokens', type: AuthResponse })
    @ApiForbiddenResponse({ description: 'Forbidden' })
    @ApiConflictResponse({
        description: 'Account exists with email or username',
    })
    @RateLimit(RateLimitEnv('auth/social/register', 5))
    @Post('social/register')
    socialRegister(@Body() socialRegisterDto: SocialRegisterDto) {
        return this.authService.handleSocialRegister(
            socialRegisterDto.provider,
            socialRegisterDto.auth,
            socialRegisterDto.username,
            socialRegisterDto.password,
        );
    }

    @ApiOperation({ summary: 'Link a social account' })
    @ApiOkResponse({ description: 'Success' })
    @ApiForbiddenResponse({ description: 'Forbidden' })
    @RateLimit(RateLimitEnv('auth/social/link', 10))
    @Post('social/link')
    @UseAuth(Token.ACCESS, { account: true })
    socialLink(@Request() req, @Body() socialLoginDto: SocialLoginDto) {
        return this.authService.handleSocialLink(
            req.user.id,
            socialLoginDto.provider,
            socialLoginDto.auth,
        );
    }

    @ApiOperation({ summary: 'Unlink a social account' })
    @ApiOkResponse({ description: 'Success' })
    @ApiForbiddenResponse({ description: 'Forbidden' })
    @RateLimit(RateLimitEnv('auth/social/unlink', 10))
    @Post('social/unlink')
    @UseAuth(Token.ACCESS, { account: true })
    socialUnlink(@Request() req, @Body() socialUnlinkDto: SocialUnlinkDto) {
        return this.authService.handleSocialUnlink(
            req.user.id,
            socialUnlinkDto.provider,
        );
    }

    @ApiOperation({
        summary: 'Redirect to the relevant OAuth page for a provider.',
    })
    @Get('social/oauth/:provider')
    socialOauth(
        @Param('provider') provider: string,
        @Query('intent') intent,
        @Res() res,
    ) {
        const protocol =
            process.env.USE_HTTP.toLowerCase() == 'yes' ? 'http' : 'https';
        const redirect = `${protocol}://${process.env.SERVER_ADDRESS || 'localhost'
            }${process.env.SERVER_PORT &&
                Number(process.env.SERVER_PORT) != protocolPorts[protocol]
                ? ':' + process.env.SERVER_PORT
                : ''
            }/auth/social/oauth/${provider}/callback`;

        switch (provider) {
            case 'discord':
                res.redirect(
                    `https://discord.com/api/oauth2/authorize?client_id=${process.env.SOCIAL_DISCORD_CLIENT_ID
                    }&redirect_uri=${redirect}&response_type=code&scope=identify%20email${intent ? `&state=${intent}` : ''
                    }`,
                );
                break;
            case 'github':
                res.redirect(
                    `https://github.com/login/oauth/authorize?client_id=${process.env.SOCIAL_GITHUB_CLIENT_ID
                    }&redirect_uri=${redirect}&response_type=code&scope=identify%20email${intent ? `&state=${intent}` : ''
                    }`,
                );
                break;
            default:
                res.redirect(process.env.SOCIAL_OAUTH_REDIRECT);
                break;
        }
    }

    @ApiOperation({ summary: 'Callback URL for login provider OAuth' })
    @RateLimit(RateLimitEnv('auth/social/oauth/callback', 10))
    @Get('social/oauth/:provider/callback')
    async socialOauthCallback(
        @Param('provider') provider: string,
        @Query('code') code: string,
        @Query('state') state: string,
        @Res() res,
    ) {
        let credential = code;

        switch (provider) {
            case 'discord':
                if (process.env.SOCIAL_DISCORD_ENABLE == "yes")
                    credential = await redeemDiscordOAuthCode(code);
                break;
            case 'github':
                if (process.env.SOCIAL_GITHUB_ENABLE == "yes")
                    credential = await redeemGitHubOAuthCode(code);
                break;
        }

        res.redirect(
            `${process.env.SOCIAL_OAUTH_REDIRECT
            }?provider=${provider}&credential=${credential}${state ? `&intent=${state}` : ''
            }`,
        );
    }

    @ApiOperation({ summary: 'Delete account' })
    @ApiOkResponse({ description: 'Success' })
    @ApiForbiddenResponse({ description: 'Forbidden' })
    @RateLimit(RateLimitEnv('auth/delete', 5))
    @Post('delete')
    @UseAuth(Token.ACCESS, { account: true })
    accountDelete(@Request() req) {
        return this.authService.handleDeleteAccount(req.user.id);
    }

    @ApiOperation({ summary: 'Update password on account' })
    @ApiOkResponse({ description: 'Success' })
    @ApiForbiddenResponse({ description: 'Forbidden' })
    @RateLimit(RateLimitEnv('auth/password', 5))
    @Post('changepassword')
    @UseAuth(Token.ACCESS, { account: true })
    changePassword(@Request() req, @Body() changePasswordDto: ChangePasswordDto) {
        return this.usersService.changePassword(req.user.id, changePasswordDto.password, changePasswordDto.oldPassword);
    }
}
