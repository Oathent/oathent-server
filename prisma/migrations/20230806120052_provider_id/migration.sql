/*
  Warnings:

  - A unique constraint covering the columns `[providerId]` on the table `SocialLogin` will be added. If there are existing duplicate values, this will fail.
  - Added the required column `providerId` to the `SocialLogin` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "SocialLogin" ADD COLUMN     "providerId" TEXT NOT NULL;

-- CreateIndex
CREATE UNIQUE INDEX "SocialLogin_providerId_key" ON "SocialLogin"("providerId");
