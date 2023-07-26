import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsStrongPassword, MinLength } from 'class-validator';

export class LoginDto {
    @ApiProperty({
        description: 'The username for the account',
        example: "BarnabWhy",
    })
    @IsNotEmpty()
    readonly username: string;

    @ApiProperty({
        description: 'The password for the account',
        example: "password123",
    })
    @IsNotEmpty()
    readonly password: string;
}

export class RegisterDto {
    @IsNotEmpty()
    @ApiProperty({
        description: 'The username for the account',
        example: "BarnabWhy",
    })
    readonly username: string;

    @IsNotEmpty()
    @IsEmail()
    @ApiProperty({
        description: 'The email for the account',
        example: "me@example.com",
    })
    readonly email: string;

    @IsNotEmpty()
    @IsStrongPassword()
    @ApiProperty({
        description: 'The password for the account',
        example: "password123",
    })
    readonly password: string;
}