import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { configDotenv } from 'dotenv';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';
import { SCOPES, initialiseScopes } from './auth/scopes';

configDotenv({
  path: 'postgres.env'
});
configDotenv();

async function bootstrap() {
  await initialiseScopes();

  const app = await NestFactory.create(AppModule);
  app.enableCors();
  app.useGlobalPipes(new ValidationPipe());

  const docsConfig = new DocumentBuilder()
    .setTitle('VersAuth API')
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
  SwaggerModule.setup('docs', app, document);

  await app.listen(3000);
}
bootstrap();
