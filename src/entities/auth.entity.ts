import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class AuthResponse {
    @ApiProperty({
        description: 'The access token for the account',
        example: 'SOME JWT ACCESS TOKEN',
    })
    accessToken: string;

    @ApiProperty({
        description: 'The refresh token for the account',
        example: 'SOME JWT REFRESH TOKEN',
    })
    refreshToken: string;
}

export class ProfileResponse {
    @ApiProperty({ description: 'The snowflake ID for the account' })
    id: bigint;

    @ApiProperty({ description: 'The username for the account' })
    username: string;

    @ApiPropertyOptional({
        description:
            'The email for the account (Only returned for account tokens and tokens with the **user:email** scope)',
    })
    email?: string;

    @ApiProperty({ description: 'Whether the account is verified' })
    verified: boolean;
}

export class AuthRefreshResponse {
    @ApiProperty({
        description: 'The access token for the account',
        example: 'SOME JWT ACCESS TOKEN',
    })
    accessToken: string;
}
