import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsStrongPassword } from 'class-validator';

export class LoginDto {
    @ApiProperty({
        description: 'The username for the account',
        example: 'BarnabWhy',
    })
    @IsNotEmpty()
    readonly username: string;

    @ApiProperty({
        description: 'The password for the account',
        example: 'password123',
    })
    @IsNotEmpty()
    readonly password: string;
}

const strongPassOptions = {
    minLength:
        process.env.PASSWORD_MIN_LENGTH &&
        !isNaN(Number(process.env.PASSWORD_MIN_LENGTH))
            ? Number(process.env.PASSWORD_MIN_LENGTH)
            : 8,
    minLowercase:
        process.env.PASSWORD_MIN_LOWERCASE &&
        !isNaN(Number(process.env.PASSWORD_MIN_LOWERCASE))
            ? Number(process.env.PASSWORD_MIN_LENGTH)
            : 1,
    minUppercase:
        process.env.PASSWORD_MIN_UPPERCASE &&
        !isNaN(Number(process.env.PASSWORD_MIN_UPPERCASE))
            ? Number(process.env.PASSWORD_MIN_LENGTH)
            : 1,
    minNumbers:
        process.env.PASSWORD_MIN_NUMBERS &&
        !isNaN(Number(process.env.PASSWORD_MIN_NUMBERS))
            ? Number(process.env.PASSWORD_MIN_LENGTH)
            : 1,
    minSymbols:
        process.env.PASSWORD_MIN_SYMBOLS &&
        !isNaN(Number(process.env.PASSWORD_MIN_SYMBOLS))
            ? Number(process.env.PASSWORD_MIN_LENGTH)
            : 0,
};

export class RegisterDto {
    @IsNotEmpty()
    @ApiProperty({
        description: 'The username for the account',
        example: 'BarnabWhy',
    })
    readonly username: string;

    @IsNotEmpty()
    @IsEmail({}, { message: 'Email address must be valid' })
    @ApiProperty({
        description: 'The email for the account',
        example: 'me@example.com',
    })
    readonly email: string;

    @IsNotEmpty()
    @IsStrongPassword(strongPassOptions, {
        message: 'Password is not strong enough',
    })
    @ApiProperty({
        description: 'The password for the account',
        example: 'password123',
    })
    readonly password: string;
}

export class RequestResetPasswordDto {
    @IsNotEmpty()
    @IsEmail({}, { message: 'Email address must be valid' })
    @ApiProperty({
        description: 'The email for the account',
        example: 'me@example.com',
    })
    readonly email: string;
}

export class ResetPasswordDto {
    @IsNotEmpty()
    @IsStrongPassword(strongPassOptions, {
        message: 'Password is not strong enough',
    })
    @ApiProperty({
        description: 'The new password for the account',
        example: 'password123',
    })
    readonly password: string;
}
