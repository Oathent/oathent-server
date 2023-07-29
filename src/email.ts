import { User } from '@prisma/client';
import * as nodemailer from 'nodemailer';

let transporter: nodemailer.Transporter;

export function initialiseEmail() {
    if (!process.env.EMAIL_HOST) throw new Error('No email host set in .env');
    if (!process.env.EMAIL_USER) throw new Error('No email user set in .env');
    if (!process.env.EMAIL_PASS)
        throw new Error('No email password set in .env');

    transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port:
            process.env.EMAIL_PORT && !isNaN(Number(process.env.EMAIL_PORT))
                ? Number(process.env.EMAIL_PORT)
                : 587,
        secure: process.env.EMAIL_SECURE == 'yes',
        requireTLS: process.env.EMAIL_NO_TLS != 'yes',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
    });
}

const protocolPorts: { [key: string]: number } = {
    http: 80,
    https: 443,
};

export async function sendVerifyEmail(
    user: User,
    code: string,
): Promise<boolean> {
    if (!transporter) return false;

    try {
        const protocol =
            process.env.USE_HTTP.toLowerCase() == 'yes' ? 'http' : 'https';
        let verifyUrl = `${protocol}://${
            process.env.SERVER_ADDRESS || 'localhost'
        }${
            process.env.SERVER_PORT &&
            Number(process.env.SERVER_PORT) != protocolPorts[protocol]
                ? ':' + process.env.SERVER_PORT
                : ''
        }/auth/verify/?code=${code}`;
        if (process.env.VERIFY_EMAIL_URL)
            verifyUrl = process.env.VERIFY_EMAIL_URL.includes('{code}')
                ? process.env.VERIFY_EMAIL_SUBJECT.replaceAll('{code}', code)
                : `${process.env.VERIFY_EMAIL_URL}?code=${code}`;

        let subject = `Account verification for ${user.username}`;
        if (process.env.VERIFY_EMAIL_SUBJECT)
            subject = process.env.VERIFY_EMAIL_SUBJECT.includes('{user}')
                ? process.env.VERIFY_EMAIL_SUBJECT.replaceAll('{user}', user.username)
                : `${user.username}: ${process.env.VERIFY_EMAIL_SUBJECT}`;

        let html = `<p>Please click this link to verify your account:<br><a href="${verifyUrl}">${verifyUrl}</a></p>`;
        if (process.env.VERIFY_EMAIL_HTML)
            html = process.env.VERIFY_EMAIL_HTML.includes('{url}')
                ? process.env.VERIFY_EMAIL_HTML.replaceAll(
                      '{user}',
                      user.username,
                  ).replaceAll('{url}', verifyUrl)
                : `${process.env.VERIFY_EMAIL_HTML.replaceAll(
                      '{user}',
                      user.username,
                  )}<br><a href="${verifyUrl}">Verify</a>`;

        const info = await transporter.sendMail({
            to: user.email,
            from: process.env.EMAIL_USER,
            subject,
            text: `Please click this link to verify your account: ${verifyUrl}`,
            html,
        });

        return info.rejected.length == 0;
    } catch (e) {
        return false;
    }
}

export async function sendResetEmail(
    user: User,
    code: string,
): Promise<boolean> {
    if (!transporter) return false;

    try {
        const protocol =
            process.env.USE_HTTP.toLowerCase() == 'yes' ? 'http' : 'https';
        let resetUrl = `${protocol}://${
            process.env.SERVER_ADDRESS || 'localhost'
        }${
            process.env.SERVER_PORT &&
            Number(process.env.SERVER_PORT) != protocolPorts[protocol]
                ? ':' + process.env.SERVER_PORT
                : ''
        }/auth/reset/?code=${code}`;
        if (process.env.PASS_RESET_EMAIL_URL)
            resetUrl = process.env.PASS_RESET_EMAIL_URL.includes('{code}')
                ? process.env.PASS_RESET_EMAIL_SUBJECT.replaceAll('{code}', code)
                : `${process.env.PASS_RESET_EMAIL_URL}?code=${code}`;

        let subject = `Password reset for ${user.username}`;
        if (process.env.PASS_RESET_EMAIL_SUBJECT)
            subject = process.env.PASS_RESET_EMAIL_SUBJECT.includes('{user}')
                ? process.env.PASS_RESET_EMAIL_SUBJECT.replaceAll('{user}', user.username)
                : `${user.username}: ${process.env.PASS_RESET_EMAIL_SUBJECT}`;

        let html = `<p>Please click this link to reset the password for your account:<br><a href="${resetUrl}">${resetUrl}</a></p>`;
        if (process.env.PASS_RESET_EMAIL_HTML)
            html = process.env.PASS_RESET_EMAIL_HTML.includes('{url}')
                ? process.env.PASS_RESET_EMAIL_HTML.replaceAll(
                      '{user}',
                      user.username,
                  ).replaceAll('{url}', resetUrl)
                : `${process.env.PASS_RESET_EMAIL_HTML.replaceAll(
                      '{user}',
                      user.username,
                  )}<br><a href="${resetUrl}">Reset</a>`;

        console.log(html);

        const info = await transporter.sendMail({
            to: user.email,
            from: process.env.EMAIL_USER,
            subject,
            text: `Please click this link to reset your account: ${resetUrl}`,
            html,
        });

        return info.rejected.length == 0;
    } catch (e) {
        return false;
    }
}