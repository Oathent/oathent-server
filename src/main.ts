import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { configDotenv } from 'dotenv';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';
import { SCOPES, initialiseScopes } from './auth/scopes';
import * as fs from 'fs/promises';
import { initialiseEmail } from './email';
import { existsSync } from 'fs';

configDotenv({
    path: 'postgres.env'
});
configDotenv();

async function bootstrap() {
    if (!process.env.DATABASE_URL)
        throw new Error("DATABASE_URL was not defined in .env!")

    await initialiseScopes();

    if(!process.env.DISABLE_VERIFICATION || process.env.DISABLE_VERIFICATION != "yes")
        initialiseEmail();

    let port = 80;
    let httpsOptions;

    if (!process.env.USE_HTTP || process.env.USE_HTTP.toLowerCase() != "yes") {
        port = 443;
        httpsOptions = {
            key: await fs.readFile('../secrets/private-key.pem'),
            cert: await fs.readFile('../secrets/public-certificate.pem'),
        };
    }

    const app = await NestFactory.create(AppModule, { httpsOptions });
    app.enableCors();
    app.useGlobalPipes(new ValidationPipe());

    if (!process.env.DISABLE_SWAGGER || process.env.DISABLE_SWAGGER.toLowerCase() != "yes") {
        const docsConfig = new DocumentBuilder()
            .setTitle('Oathent API')
            .addBearerAuth({ type: 'http' }, 'Account access token')
            .addBearerAuth({ type: 'http' }, 'Account refresh token')
            .addBearerAuth({ type: 'http' }, 'OAuth2 access token')
            .addBearerAuth({ type: 'http' }, 'OAuth2 refresh token')
            .addBearerAuth({ type: 'http' }, 'OAuth2 auth code')
            .addBearerAuth({ type: 'http' }, 'OAuth2 device code')
            .setVersion(process.env.npm_package_version || '0.0.0')
            .setDescription(`Authentication and OAuth2 API<br><br>**Scopes:** ${Object.keys(SCOPES).join(', ')}`)
            .build();
        const document = SwaggerModule.createDocument(app, docsConfig);
        SwaggerModule.setup('docs', app, document, {
            customCssUrl: "swagger.css",
            customCss: existsSync("swagger.custom.css") ? await fs.readFile("swagger.custom.css", 'utf-8') : undefined,
            customSiteTitle: "Oathent API Docs"
        });
    }

    await app.listen(process.env.SERVER_PORT && !isNaN(Number(process.env.SERVER_PORT)) ? Number(process.env.SERVER_PORT) : port);
}
bootstrap();
