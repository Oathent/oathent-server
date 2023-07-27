import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtModule } from '@nestjs/jwt';
import { jwtConstants } from './constants';
import { OauthService } from 'src/oauth/oauth.service';
import { UsersService } from 'src/users/users.service';

@Module({
    imports: [
        JwtModule.register({
            global: true,
            secret: jwtConstants.accessSecret,
            signOptions: { expiresIn: jwtConstants.accessExpiry },
        }),
    ],
    controllers: [AuthController],
    providers: [AuthService, UsersService, OauthService],
    exports: [AuthService],
})
export class AuthModule {}
