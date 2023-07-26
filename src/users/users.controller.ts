import { Request, Controller, Get } from '@nestjs/common';
import { Token, UseAuth } from '../auth/auth.guard';
import { ProfileResponse } from '../entities/auth.entity'
import { ApiTags, ApiOperation, ApiOkResponse } from '@nestjs/swagger';

@ApiTags('user')
@Controller('user')
export class UsersController {
    constructor() { }

    @ApiOperation({ summary: 'View user profile' })
    @ApiOkResponse({ description: 'User profile', type: ProfileResponse })
    @UseAuth(Token.ACCESS, { scopes: ['user:email'] })
    @Get('profile')
    getProfile(@Request() req) {
        return req.user;
    }
}
