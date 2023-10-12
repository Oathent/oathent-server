/*
  Warnings:

  - The values [STEAM] on the enum `SocialProvider` will be removed. If these variants are still used in the database, this will fail.

*/
-- AlterEnum
BEGIN;
CREATE TYPE "SocialProvider_new" AS ENUM ('GOOGLE', 'DISCORD', 'GITHUB');
ALTER TABLE "SocialLogin" ALTER COLUMN "provider" TYPE "SocialProvider_new" USING ("provider"::text::"SocialProvider_new");
ALTER TYPE "SocialProvider" RENAME TO "SocialProvider_old";
ALTER TYPE "SocialProvider_new" RENAME TO "SocialProvider";
DROP TYPE "SocialProvider_old";
COMMIT;
