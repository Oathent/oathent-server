import { OAuth2Client } from 'google-auth-library';
import { protocolPorts } from './email';

const client = new OAuth2Client();
export async function verifyGoogleToken(token: string) {
    try {
        if (process.env.SOCIAL_GOOGLE_ENABLE == 'no') return { success: false };

        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: process.env.SOCIAL_GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        const userId = payload['sub'];
        const userName = payload['name'];
        const userGivenName = payload['given_name'];
        const userEmail = payload['email'];
        const verified = payload['email_verified'];
        return { success: true, userId, userName, userGivenName, userEmail, verified }; 
    } catch (e) {
        return { success: false };
    }
}

export async function redeemDiscordOAuthCode(code: string) {
    const protocol =
        process.env.USE_HTTP.toLowerCase() == 'yes' ? 'http' : 'https';

    const redirect = `${protocol}://${
        process.env.SERVER_ADDRESS || 'localhost'
    }${
        process.env.SERVER_PORT &&
        Number(process.env.SERVER_PORT) != protocolPorts[protocol]
            ? ':' + process.env.SERVER_PORT
            : ''
    }/auth/social/oauth/discord/callback`;

    const body = new URLSearchParams();
    body.append('code', code);
    body.append('client_id', process.env.SOCIAL_DISCORD_CLIENT_ID);
    body.append('client_secret', process.env.SOCIAL_DISCORD_CLIENT_SECRET);
    body.append('grant_type', 'authorization_code');
    body.append('redirect_uri', redirect);

    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
        method: 'POST',
        body,
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
    });

    const data = await tokenRes.json();
    const { access_token } = data;

    return access_token;
}

export async function verifyDiscordOAuth(token: string) {
    try {
        if (process.env.SOCIAL_DISCORD_ENABLE != 'yes')
            return { success: false };

        const res = await fetch('https://discord.com/api/users/@me', {
            headers: {
                authorization: `Bearer ${token}`,
            },
        });

        const user = await res.json();

        return {
            success: true,
            userId: user.id,
            username: user.username,
            userEmail: user.email,
            verified: user.verified,
        };
    } catch (e) {
        return { success: false };
    }
}

export async function redeemGitHubOAuthCode(code: string) {
    const body = new URLSearchParams();
    body.append('code', code);
    body.append('client_id', process.env.SOCIAL_GITHUB_CLIENT_ID);
    body.append('client_secret', process.env.SOCIAL_GITHUB_CLIENT_SECRET);

    const tokenRes = await fetch(
        'https://github.com/login/oauth/access_token',
        {
            method: 'POST',
            body,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                Accept: 'application/json',
            },
        },
    );

    const data = await tokenRes.json();
    const { access_token } = data;

    return access_token;
}

export async function verifyGitHubOAuth(token: string) {
    try {
        if (process.env.SOCIAL_GITHUB_ENABLE != 'yes')
            return { success: false };

        const res = await fetch('https://api.github.com/user', {
            headers: {
                authorization: `Bearer ${token}`,
                Accept: 'application/json',
            },
        });

        const user = await res.json();

        const emailsRes = await fetch('https://api.github.com/user/emails', {
            headers: {
                authorization: `Bearer ${token}`,
                Accept: 'application/json',
            },
        });

        const emails = await emailsRes.json();

        if (emails.length == 0)
            // sanity check
            return { success: false };

        return {
            success: true,
            userId: user.id.toString(),
            username: user.login,
            userEmail: emails.find((e) => e.primary).email,
            verified: emails.find((e) => e.primary).verified,
        };
    } catch (e) {
        return { success: false };
    }
}
