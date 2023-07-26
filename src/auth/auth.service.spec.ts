import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { OauthService } from 'src/oauth/oauth.service';
import { JwtModule } from '@nestjs/jwt';
import { jwtConstants } from './constants';
import { UsersService } from 'src/users/users.service';

describe('AuthService', () => {
  let service: AuthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [
        JwtModule.register({
          global: true,
          secret: jwtConstants.accessSecret,
          signOptions: { expiresIn: jwtConstants.accessExpiry },
        }),
      ],
      providers: [AuthService, UsersService, OauthService],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
