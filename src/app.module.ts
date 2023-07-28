import { Module } from '@nestjs/common';
import { ThrottlerModule } from '@nestjs/throttler';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { OauthModule } from './oauth/oauth.module';

@Module({
    imports: [
        ThrottlerModule.forRoot({
            limit: 100,
            ttl: 60,
        }),
        AuthModule,
        UsersModule,
        OauthModule,
    ],
    controllers: [AppController],
    providers: [AppService],
})
export class AppModule {}
