import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { OauthService } from 'src/oauth/oauth.service';

@Module({
    imports: [],
    providers: [UsersService, OauthService],
    controllers: [UsersController],
    exports: [UsersService],
})
export class UsersModule {}
