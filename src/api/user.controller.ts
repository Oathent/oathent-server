import { Controller, Get, Session } from '@nestjs/common';
import { UserService } from './user.service';

@Controller('api/user')
export class UserController {
    constructor(private readonly userService: UserService) { }

    @Get()
    getHello(): string {
        return this.userService.getHello();
    }
}