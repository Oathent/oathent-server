import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { DeviceCodeStatus } from 'src/oauth/deviceCodes';

export class AppDetailsResponse {
    @ApiProperty({ description: 'The snowflake ID for the application' })
    id: bigint;

    @ApiProperty({ description: 'The name of the application' })
    name: string;

    @ApiProperty({ description: "The path to the application's avatar" })
    avatarPath: string;

    @ApiProperty({
        description: 'How many users have authorized the application',
    })
    useCount: number;
}

export class AuthorizeResponse {
    @ApiProperty({ description: 'Whether the authorization succeeded' })
    success: boolean;

    @ApiPropertyOptional({
        description:
            "The returned auth code (if the 'auth_code' flow is being used)",
    })
    code: string;
}

export class RejectResponse {
    @ApiProperty({ description: 'Whether the authorization succeeded' })
    success: boolean;
}

export class CreateDeviceCodeResponse {
    @ApiProperty({
        description: 'The device code to be used in the auth request',
    })
    code: string;
}

export class DeviceCodeRedeemResponse {
    @ApiProperty({ description: 'The current status of the device code' })
    status: DeviceCodeStatus;

    @ApiPropertyOptional({
        description: 'The access token for the application',
        example: 'SOME JWT ACCESS TOKEN',
    })
    accessToken: string;

    @ApiPropertyOptional({
        description: 'The refresh token for the application',
        example: 'SOME JWT REFRESH TOKEN',
    })
    refreshToken: string;
}

export class TokenDetailsResponse {
    @ApiProperty({
        description: 'The snowflake ID of the application this token is for',
    })
    appId: bigint;

    @ApiProperty({
        description: 'The list of scopes this token is permitted to use',
    })
    scopes: string[];
}

export class AuthedAppsResponse {
    @ApiProperty({ description: 'The timestamp for the time that the app was authorised' })
    authedAt: number;

    @ApiProperty({ description: 'The details of the app' })
    details: AppDetailsResponse;
}