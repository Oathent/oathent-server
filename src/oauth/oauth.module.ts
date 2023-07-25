import { Module } from '@nestjs/common';
import { OauthController } from './oauth.controller';
import { OauthService } from './oauth.service';
import { UsersService } from 'src/users/users.service';

@Module({
  controllers: [OauthController],
  providers: [OauthService, UsersService]
})
export class OauthModule {}
