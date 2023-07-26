import { Test, TestingModule } from '@nestjs/testing';
import { OauthController } from './oauth.controller';
import { JwtModule } from '@nestjs/jwt';
import { jwtConstants } from 'src/auth/constants';
import { UsersService } from 'src/users/users.service';
import { OauthService } from './oauth.service';

describe('OauthController', () => {
  let controller: OauthController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [
        JwtModule.register({
          global: true,
          secret: jwtConstants.accessSecret,
          signOptions: { expiresIn: jwtConstants.accessExpiry },
        }),
      ],
      controllers: [OauthController],
      providers: [OauthService, UsersService],
    }).compile();

    controller = module.get<OauthController>(OauthController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
