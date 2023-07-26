import { Test, TestingModule } from '@nestjs/testing';
import { OauthService } from './oauth.service';
import { UsersService } from 'src/users/users.service';
import { JwtModule } from '@nestjs/jwt';
import { jwtConstants } from 'src/auth/constants';

describe('OauthService', () => {
  let service: OauthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [
        JwtModule.register({
          global: true,
          secret: jwtConstants.accessSecret,
          signOptions: { expiresIn: jwtConstants.accessExpiry },
        }),
      ],
      providers: [OauthService, UsersService]
    }).compile();

    service = module.get<OauthService>(OauthService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
