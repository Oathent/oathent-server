/*
  Warnings:

  - The primary key for the `SocialLogin` table will be changed. If it partially fails, the table could be left without primary key constraint.

*/
-- DropIndex
DROP INDEX "SocialLogin_providerId_key";

-- AlterTable
ALTER TABLE "SocialLogin" DROP CONSTRAINT "SocialLogin_pkey",
ADD CONSTRAINT "SocialLogin_pkey" PRIMARY KEY ("provider", "providerId");
