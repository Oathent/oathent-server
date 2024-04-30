import {
    Controller,
    Post,
    Request,
    Body,
    BadRequestException,
    UnauthorizedException,
    Param,
    Get,
    ForbiddenException,
} from '@nestjs/common';
import { OauthService } from './oauth.service';
import { Token, UseAuth } from 'src/auth/auth.guard';
import { getDeviceCodeStatus } from './deviceCodes';
import {
    ApiTags,
    ApiOperation,
    ApiBadRequestResponse,
    ApiOkResponse,
} from '@nestjs/swagger';
import {
    AppDetailsResponse,
    AuthedAppsResponse,
    AuthorizeResponse,
    CreateDeviceCodeResponse,
    DeviceCodeRedeemResponse,
    RejectResponse,
    TokenDetailsResponse,
} from 'src/entities/oauth.entity';
import {
    AuthorizeRejectDto,
    CreateDeviceCodeDto,
    CreateSubtokenDto,
    RevokeTokenDto,
} from 'src/dto/oauth.dto';
import { AuthRefreshResponse, AuthResponse } from 'src/entities/auth.entity';
import { RateLimit, RateLimitEnv } from 'src/ratelimit.guard';
import { SCOPES } from 'src/auth/scopes';

@ApiTags('oauth')
@Controller('oauth')
export class OauthController {
    constructor(private oauthService: OauthService) {}

    @ApiOperation({ summary: 'View app details' })
    @ApiOkResponse({ description: 'App details', type: AppDetailsResponse })
    @Get('/app/:appId')
    getApp(@Param('appId') appId: bigint) {
        return this.oauthService.getAppDetails(appId);
    }

    @ApiOperation({ summary: 'View scope IDs for a scope number' })
    @ApiOkResponse({ description: 'Scopes', type: [String] })
    @Get('/scopes/:scope')
    getScopes(@Param('scope') scope: number) {
        return this.oauthService.getScopeStrings(scope);
    }

    @ApiOperation({ summary: 'Authorize an OAuth2 application' })
    @ApiOkResponse({ description: 'App authorized', type: AuthorizeResponse })
    @RateLimit(RateLimitEnv('oauth/authorize', 10))
    @UseAuth(Token.ACCESS, { verified: true, account: true })
    @Post('/authorize')
    authorize(@Request() req, @Body() authorizeDto: AuthorizeRejectDto) {
        return this.oauthService.authorizeApp(
            req.user.id,
            authorizeDto.appId,
            authorizeDto.scope,
            authorizeDto.flow,
            authorizeDto.code,
            authorizeDto.redirect,
        );
    }

    @ApiOperation({ summary: 'Reject an OAuth2 application' })
    @ApiOkResponse({ description: 'App rejected', type: RejectResponse })
    @RateLimit(RateLimitEnv('oauth/reject', 10))
    @UseAuth(Token.ACCESS, { verified: true, account: true })
    @Post('/reject')
    reject(@Request() req, @Body() rejectDto: AuthorizeRejectDto) {
        return this.oauthService.rejectApp(
            req.user.id,
            rejectDto.appId,
            rejectDto.scope,
            rejectDto.flow,
            rejectDto.code,
        );
    }

    @ApiOperation({ summary: 'Reedem OAuth2 tokens using an auth code' })
    @ApiOkResponse({ description: 'OAuth2 tokens', type: AuthResponse })
    @UseAuth(Token.CODE)
    @Post('/token')
    getToken(@Request() req) {
        return this.oauthService.createToken(
            req.oauthCode.userId,
            req.oauthCode.appId,
            req.oauthCode.scope,
        );
    }

    @ApiOperation({
        summary: 'Generate a new OAuth2 access token using a refresh token',
    })
    @ApiOkResponse({ description: 'Success', type: AuthRefreshResponse })
    @RateLimit(RateLimitEnv('oauth/refresh', 1))
    @UseAuth(Token.REFRESH, { verified: true })
    @Post('refresh')
    refreshToken(@Request() req) {
        return this.oauthService.refreshToken(
            req.user.id,
            req.auth.appId,
            req.auth.scope,
        );
    }

    @ApiOperation({
        summary: 'Generate a new device code to be used in an auth request',
    })
    @RateLimit(RateLimitEnv('oauth/device/create', 5))
    @ApiOkResponse({ description: 'Success', type: CreateDeviceCodeResponse })
    @Post('/device/create')
    async createDeviceCode(
        @Request() req,
        @Body() createDeviceCodeDto: CreateDeviceCodeDto,
    ) {
        return await this.oauthService.createDeviceCode(
            req.ip,
            createDeviceCodeDto.seed,
        );
    }

    @ApiOperation({ summary: 'Redeem tokens using an authorized device code' })
    @ApiOkResponse({
        description: 'Status / OAuth2 tokens',
        type: DeviceCodeRedeemResponse,
    })
    @RateLimit(RateLimitEnv('oauth/device/redeem', 30))
    @UseAuth(Token.DEVICE_CODE)
    @Post('/device/redeem')
    async redeemDeviceCode(@Request() req) {
        const status = await getDeviceCodeStatus(req.deviceCode);
        if (status != 'authed') return { status };

        const { accessToken, refreshToken } =
            await this.oauthService.redeemDeviceCodeToken(req.deviceCode);
        return { status, accessToken, refreshToken };
    }

    @ApiOperation({ summary: 'Revoke access tokens for an app' })
    @ApiOkResponse({ description: 'Success' })
    @ApiBadRequestResponse({ description: 'Bad Request' })
    @RateLimit(RateLimitEnv('oauth/revoke', 30))
    @UseAuth(Token.ACCESS, { verified: true })
    @Post('/revoke')
    async revoke(@Request() req, @Body() revokeTokenDto: RevokeTokenDto) {
        let appId = req.auth.appId;
        if (appId == null) {
            if (
                !revokeTokenDto.appId ||
                !(await this.oauthService.appExists(appId))
            )
                throw new BadRequestException();

            appId = revokeTokenDto.appId;
        }

        return this.oauthService.revokeApp(req.user.userId, appId);
    }

    @ApiOperation({ summary: 'Gets the details of the current token' })
    @ApiOkResponse({ description: 'Token details', type: TokenDetailsResponse })
    @ApiBadRequestResponse({ description: 'Bad Request' })
    @RateLimit(RateLimitEnv('oauth/token', 30))
    @UseAuth(Token.ACCESS)
    @Get('/token')
    async tokenDetails(@Request() req) {
        const appId = req.auth.appId;
        if (appId == null) throw new UnauthorizedException();

        return {
            appId: req.auth.appId,
            scopes: await this.oauthService.getScopeStrings(req.auth.scope),
            expiry: req.auth.expiry,
        };
    }

    @ApiOperation({ summary: 'View authed apps' })
    @ApiOkResponse({ description: 'Authed apps', type: AuthedAppsResponse })
    @RateLimit(RateLimitEnv('oauth/apps', 25))
    @UseAuth(Token.ACCESS, { scopes: ['user:apps'], account: true })
    @Get('/apps')
    getApps(@Request() req) {
        return this.oauthService.getAuthedApps(req.user.id);
    }

    @ApiOperation({ summary: 'Create a new subtoken' })
    @ApiOkResponse({ description: 'The subtoken', type: AuthResponse })
    @RateLimit(RateLimitEnv('oauth/subtoken', 25))
    @UseAuth(Token.ACCESS, { scopes: ['oauth:subtoken'] })
    @Post('/subtoken')
    createSubtoken(@Request() req, @Body() createSubtokenDto: CreateSubtokenDto) {
        const appId = req.auth.appId;
        if (appId == null) throw new UnauthorizedException();

        if (createSubtokenDto.scope & ~req.auth.scope || createSubtokenDto.scope & SCOPES['oauth:subtoken']) {
            // Some disallowed scope has been requested
            // (beyond scope of parent token or wabts to create more subtokens)
            throw new ForbiddenException();
        }

        return this.oauthService.createSubtoken(req.user.id, appId, createSubtokenDto.scope);
    }
}
