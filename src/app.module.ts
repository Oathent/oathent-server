import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { OauthModule } from './oauth/oauth.module';

@Module({
  imports: [
    AuthModule,
    UsersModule,
    OauthModule
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
