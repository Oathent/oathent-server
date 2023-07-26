import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getIndex(): string {
    return `Oathent v${process.env.npm_package_version || '0.0.0'}`;
  }
}
