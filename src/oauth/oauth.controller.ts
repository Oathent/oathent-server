import { Controller, Post, Request, Body, BadRequestException, Param, Get } from '@nestjs/common';
import { OauthService } from './oauth.service';
import { Token, UseAuth } from 'src/auth/auth.guard';
import { getDeviceCodeStatus } from './deviceCodes';

@Controller('oauth')
export class OauthController {
    constructor(
        private oauthService: OauthService,
    ) { }

    @Get('/app/:appId')
    getApp(@Param() params: any) {
        return this.oauthService.getAppDetails(params.appId);
    }
    @Get('/scopes/:scope')
    getScopes(@Param() params: any) {
        return this.oauthService.getScopeStrings(params.scope);
    }

    @UseAuth()
    @Post('/authorize')
    authorize(@Request() req, @Body() authorizeDto: Record<string, any>) {
        return this.oauthService.authorizeApp(req.user.id, req.body.appId, req.body.scope, req.body.flow, req.body.code);
    }

    @UseAuth()
    @Post('/reject')
    reject(@Request() req, @Body() rejectDto: Record<string, any>) {
        return this.oauthService.rejectApp(req.user.id, req.body.appId, req.body.scope, req.body.flow, req.body.code);
    }

    @UseAuth(Token.CODE)
    @Post('/token')
    getToken(@Request() req) {
        return this.oauthService.createToken(req.oauthCode.userId, req.oauthCode.appId, req.oauthCode.scope, req.oauthCode.allowRefresh);
    }

    @Post('/device/create')
    async createDeviceCode(@Request() req, @Body() createDeviceCodeDto: Record<string, any>) {
        return await this.oauthService.createDeviceCode(req.ip, req.body.seed);
    }
    
    @UseAuth(Token.DEVICE_CODE)
    @Post('/device/redeem')
    async redeemDeviceCode(@Request() req) {
        let status = await getDeviceCodeStatus(req.deviceCode);
        if(status != 'authed')
            return { status };

        let { accessToken, refreshToken } = await this.oauthService.redeemDeviceCodeToken(req.deviceCode);
        return { status, accessToken, refreshToken };
    }

    @UseAuth(Token.ACCESS)
    @Post('/revoke')
    revoke(@Request() req) {
        let appId = req.auth.appId;
        if (appId == null) {
            if (!req.body.appId)
                throw new BadRequestException();

            appId = req.body.appId;
        }

        return this.oauthService.revokeApp(req.user.userId, appId);
    }
}
