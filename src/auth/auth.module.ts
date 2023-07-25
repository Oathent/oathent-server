import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtModule } from '@nestjs/jwt';
import { jwtConstants } from './constants';
import { UsersModule } from 'src/users/users.module';
import { OauthService } from 'src/oauth/oauth.service';

@Module({
  imports: [
    UsersModule,
    JwtModule.register({
      global: true,
      secret: jwtConstants.accessSecret,
      signOptions: { expiresIn: jwtConstants.accessExpiry },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, OauthService],
  exports: [AuthService],
})
export class AuthModule {}
