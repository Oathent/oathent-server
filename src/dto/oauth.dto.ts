import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsInt, IsNotEmpty, IsOptional, Length, Min } from 'class-validator';

export class AuthorizeRejectDto {
    @ApiProperty({ description: 'The snowflake ID for the application' })
    @IsNotEmpty()
    readonly appId: bigint;

    @ApiProperty({ description: 'The scope requested by the application' })
    @Min(0)
    @IsInt()
    readonly scope: number;

    @ApiProperty({ description: 'The flow being used by the application' })
    @IsNotEmpty()
    readonly flow: string;

    @ApiPropertyOptional({
        description:
            "The device code (if the 'device_code' flow is being used)",
    })
    @IsOptional()
    readonly code: string;

    @ApiPropertyOptional({
        description: "The redirect_uri (if the 'auth_code' flow is being used)",
    })
    @IsOptional()
    readonly redirect: string;
}

export class CreateDeviceCodeDto {
    @ApiProperty({ description: 'The seed for the device code' })
    @Length(16)
    readonly seed: string;
}

export class RevokeTokenDto {
    @ApiPropertyOptional({
        description: 'The app ID to revoke (omit if revoking account tokens)',
    })
    readonly appId: bigint;
}

export class CreateSubtokenDto {
    @ApiProperty({
        description: 'The scopes to give the token (must be present on the parent token and cannot include subtoken creation)',
    })
    readonly scope: number;
}