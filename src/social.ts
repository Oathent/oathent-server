import { OAuth2Client } from 'google-auth-library';

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
        return { success: true, userId, userName, userGivenName, userEmail };
    } catch (e) {
        return { success: false };
    }
}
