import { JwtService } from '@nestjs/jwt';
import { User } from '@prisma/client';
import * as nodemailer from 'nodemailer';
import { jwtConstants } from './auth/constants';
import { Token } from './auth/auth.guard';

let transporter: nodemailer.Transporter;

export function initialiseEmail() {
    if (!process.env.EMAIL_HOST)
        throw new Error("No email host set in .env");
    if (!process.env.EMAIL_USER)
        throw new Error("No email user set in .env");
    if (!process.env.EMAIL_PASS)
        throw new Error("No email password set in .env");

    transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: process.env.EMAIL_PORT && !isNaN(Number(process.env.EMAIL_PORT)) ? Number(process.env.EMAIL_PORT) : 587,
        secure: process.env.EMAIL_SECURE == "yes",
        requireTLS: process.env.EMAIL_NO_TLS != "yes",
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
        logger: true
    });
}

export async function sendVerifyEmail(user: User, code: string): Promise<boolean> {
    if (!transporter)
        return false;

    try {
        let verifyUrl = "http://localhost:3000/auth/verify/?code=" + code;
        if(process.env.EMAIL_VERIFY_URL)
            verifyUrl = process.env.EMAIL_VERIFY_URL.includes("{code}") ? process.env.EMAIL_SUBJECT.replace("{code}", code) : `${process.env.EMAIL_VERIFY_URL}?code=${code}`


        let subject = `Account verification for ${user.username}`;
        if(process.env.EMAIL_SUBJECT)
            subject = process.env.EMAIL_SUBJECT.includes("{user}") ? process.env.EMAIL_SUBJECT.replace("{user}", user.username) : `${user.username}: ${process.env.EMAIL_SUBJECT}`

        let html = `Please click this link to verify your account: <a href="${verifyUrl}">${verifyUrl}</a>`;
        if(process.env.EMAIL_HTML)
            subject = process.env.EMAIL_HTML.includes("{url}") ? process.env.EMAIL_HTML.replace("{url}", verifyUrl) : `${process.env.EMAIL_HTML}<br><a href="${verifyUrl}">Verify</a>`

        const info = await transporter.sendMail({
            to: user.email,
            from: process.env.EMAIL_USER,
            subject,
            text: `Please click this link to verify your account: ${verifyUrl}`,
            html,
        });

        return info.rejected.length == 0;
    } catch(e) {
        return false;
    }
}