import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { configDotenv } from 'dotenv';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';
import { SCOPES, initialiseScopes } from './auth/scopes';
import * as fs from 'fs/promises';
import { initialiseEmail } from './email';
import { existsSync } from 'fs';
import { NestExpressApplication } from '@nestjs/platform-express';
import chalk from 'chalk';

configDotenv({
    path: 'postgres.env',
});
configDotenv();

async function bootstrap() {
    console.log(chalk.blue('[Oathent]'), chalk.cyan('Starting Oathent server'));

    if (!process.env.DATABASE_URL)
        throw new Error('DATABASE_URL was not defined in .env!');

    console.log(chalk.blue('[Oathent]'), 'Initialising scopes');
    await initialiseScopes();

    if (
        !process.env.DISABLE_VERIFICATION ||
        process.env.DISABLE_VERIFICATION != 'yes'
    ) {
        console.log(chalk.blue('[Oathent]'), 'Initialising email system');
        initialiseEmail();
    }

    let port = 80;
    let httpsOptions;

    if (!process.env.USE_HTTP || process.env.USE_HTTP.toLowerCase() != 'yes') {
        port = 443;
        console.log(chalk.blue('[Oathent]'), 'Reading SSL key pair');
        httpsOptions = {
            key: await fs.readFile('./secrets/private-key.pem'),
            cert: await fs.readFile('./secrets/public-certificate.pem'),
        };
    }

    console.log(chalk.blue('[Oathent]'), 'Creating Nest server');
    const app = await NestFactory.create<NestExpressApplication>(AppModule, {
        httpsOptions,
        logger: ['warn', 'error'],
    });

    let corsOrigins: string[] | boolean = true;
    if (process.env.CORS_ORIGINS != undefined) {
        if (process.env.CORS_ORIGINS)
            corsOrigins = process.env.CORS_ORIGINS.split(',').map((o) =>
                o.trim(),
            );
        else corsOrigins = false;
    }

    if (typeof corsOrigins != 'boolean')
        console.log(
            chalk.blue('[Oathent]'),
            'CORS Allowed Origins:',
            corsOrigins.map((o) => chalk.yellow(o)).join(', '),
        );
    else
        console.log(
            chalk.blue('[Oathent]'),
            'CORS Allowed Origins:',
            corsOrigins ? chalk.yellow('*') : chalk.red('NONE'),
        );

    app.enableCors({
        origin: corsOrigins,
    });

    if (process.env.TRUST_PROXY == 'all') {
        console.log(
            chalk.blue('[Oathent]'),
            'Trust proxy:',
            chalk.yellow('ALL'),
        );
        app.set('trust proxy', 1);
    } else if (process.env.TRUST_PROXY == 'local') {
        console.log(
            chalk.blue('[Oathent]'),
            'Trust proxy:',
            chalk.yellow('LOCAL'),
        );
        app.set('trust proxy', ['loopback', 'linklocal', 'uniquelocal']);
    } else if (process.env.TRUST_PROXY == 'cf') {
        console.log(
            chalk.blue('[Oathent]'),
            'Trust proxy:',
            chalk.yellow('CLOUDFLARE'),
        );
        const cfIPv4 = (
            await (await fetch('https://www.cloudflare.com/ips-v4')).text()
        ).split('\n');
        const cfIPv6 = (
            await (await fetch('https://www.cloudflare.com/ips-v6')).text()
        ).split('\n');

        app.set('trust proxy', [...cfIPv4, ...cfIPv6]);
    } else if (process.env.TRUST_PROXY) {
        const trusted = process.env.TRUST_PROXY.split(',').map((t) => t.trim());
        console.log(
            chalk.blue('[Oathent]'),
            'Trust proxy:',
            trusted.map((t) => chalk.yellow(t)).join(', '),
        );
        app.set('trust proxy', trusted);
    }

    if (process.env.SERVER_PORT && !isNaN(Number(process.env.SERVER_PORT)))
        port = Number(process.env.SERVER_PORT);

    console.log(chalk.blue('[Oathent]'), 'Server port:', chalk.yellow(port));

    let hostname = '0.0.0.0';
    if (process.env.SERVER_ADDRESS) hostname = process.env.SERVER_ADDRESS;

    console.log(
        chalk.blue('[Oathent]'),
        'Server address:',
        chalk.yellow(hostname),
    );

    console.log(chalk.blue('[Oathent]'), 'Initialising input validation');
    app.useGlobalPipes(new ValidationPipe());

    if (
        !process.env.DISABLE_SWAGGER ||
        process.env.DISABLE_SWAGGER.toLowerCase() != 'yes'
    ) {
        console.log(chalk.blue('[Oathent]'), 'Initialising Swagger docs');
        const docsConfig = new DocumentBuilder()
            .setTitle('Oathent API')
            .addBearerAuth({ type: 'http' }, 'Account access token')
            .addBearerAuth({ type: 'http' }, 'Account refresh token')
            .addBearerAuth({ type: 'http' }, 'OAuth2 access token')
            .addBearerAuth({ type: 'http' }, 'OAuth2 refresh token')
            .addBearerAuth({ type: 'http' }, 'OAuth2 auth code')
            .addBearerAuth({ type: 'http' }, 'OAuth2 device code')
            .setVersion(process.env.npm_package_version || '0.0.0')
            .setDescription(
                `Authentication and OAuth2 API<br><br>**Scopes:** ${Object.keys(
                    SCOPES,
                ).join(', ')}`,
            )
            .build();
        const document = SwaggerModule.createDocument(app, docsConfig);
        SwaggerModule.setup('docs', app, document, {
            customCssUrl: 'swagger.css',
            customCss: existsSync('swagger.custom.css')
                ? await fs.readFile('swagger.custom.css', 'utf-8')
                : undefined,
            customSiteTitle: 'Oathent API Docs',
        });
    }

    console.log(
        chalk.blue('[Oathent]'),
        chalk.greenBright('Listening for requests'),
    );
    await app.listen(port, hostname);
}
bootstrap();
