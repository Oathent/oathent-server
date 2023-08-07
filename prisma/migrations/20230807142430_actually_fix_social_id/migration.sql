/*
  Warnings:

  - The primary key for the `SocialLogin` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - A unique constraint covering the columns `[provider,providerId]` on the table `SocialLogin` will be added. If there are existing duplicate values, this will fail.

*/
-- AlterTable
ALTER TABLE "SocialLogin" DROP CONSTRAINT "SocialLogin_pkey",
ADD CONSTRAINT "SocialLogin_pkey" PRIMARY KEY ("userId", "provider");

-- CreateIndex
CREATE UNIQUE INDEX "SocialLogin_provider_providerId_key" ON "SocialLogin"("provider", "providerId");
