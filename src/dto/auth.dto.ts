import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { MFAMethod } from '@prisma/client';
import {
    IsEmail,
    IsNotEmpty,
    IsOptional,
    IsStrongPassword,
} from 'class-validator';

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

    @ApiProperty({
        description: 'MFA for the account (if needed)',
    })
    readonly mfa: {
        method: MFAMethod,
        credential: string,
    };
}

export const strongPassOptions = {
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

export class SocialLoginDto {
    @IsNotEmpty()
    @ApiProperty({
        description: 'The provider for the social login',
        example: 'google',
    })
    readonly provider: string;

    @IsNotEmpty()
    @ApiProperty({
        description: 'The authentication provided by the social login',
    })
    readonly auth: string;
}

export class SocialRegisterDto {
    @IsNotEmpty()
    @ApiProperty({
        description: 'The provider for the social login',
        example: 'google',
    })
    readonly provider: string;

    @IsNotEmpty()
    @ApiProperty({
        description: 'The authentication provided by the social login',
    })
    readonly auth: string;

    @ApiProperty({
        description: 'The username for the account',
        example: 'BarnabWhy',
    })
    readonly username: string;

    @IsOptional()
    @IsStrongPassword(strongPassOptions, {
        message: 'Password is not strong enough',
    })
    @ApiPropertyOptional({
        description: 'The password for the account',
        example: 'password123',
    })
    readonly password: string;
}

export class SocialUnlinkDto {
    @IsNotEmpty()
    @ApiProperty({
        description: 'The provider for the social login',
        example: 'google',
    })
    readonly provider: string;
}

export class ChangePasswordDto {
    @ApiProperty({
        description: 'The old password for the account',
        example: 'password123',
    })
    readonly oldPassword: string;

    @IsNotEmpty()
    @IsStrongPassword(strongPassOptions, {
        message: 'Password is not strong enough',
    })
    @ApiProperty({
        description: 'The new password for the account',
        example: 'password1234',
    })
    readonly password: string;
}

import type { AuthenticatorAttestationResponseJSON } from '@simplewebauthn/types';

export class WebAuthnRegistrationDto {
    readonly id: string;
    readonly rawId: string;
    readonly response: AuthenticatorAttestationResponseJSON;
    readonly authenticatorAttachment?: AuthenticatorAttachment;
    readonly clientExtensionResults: AuthenticationExtensionsClientOutputs;
    readonly type: PublicKeyCredentialType;
}