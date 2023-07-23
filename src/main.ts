import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { configDotenv } from 'dotenv';
import * as session from 'express-session';

configDotenv({
  path: 'postgres.env'
});
configDotenv();

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  app.use(
    session({
      name: 'session-token',
      secret: process.env.SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      cookie: {
        maxAge: 30 * 86400 * 1000,
        httpOnly: false,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
      },
    }),
  );

  await app.listen(3000);
}
bootstrap();
