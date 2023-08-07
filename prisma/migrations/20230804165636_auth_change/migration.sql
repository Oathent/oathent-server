/*
  Warnings:

  - The primary key for the `Auth` table will be changed. If it partially fails, the table could be left without primary key constraint.
  - You are about to drop the column `id` on the `Auth` table. All the data in the column will be lost.
  - Added the required column `authedAt` to the `Auth` table without a default value. This is not possible if the table is not empty.

*/
-- CreateEnum
CREATE TYPE "MFAMethod" AS ENUM ('TOTP');

-- CreateEnum
CREATE TYPE "SocialProvider" AS ENUM ('GOOGLE', 'DISCORD');

-- AlterTable
ALTER TABLE "Auth" DROP CONSTRAINT "Auth_pkey",
DROP COLUMN "id",
ADD COLUMN     "authedAt" TIMESTAMP(3) NOT NULL,
ADD CONSTRAINT "Auth_pkey" PRIMARY KEY ("userId", "applicationId");

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "mfaMethod" "MFAMethod";

-- CreateTable
CREATE TABLE "SocialLogin" (
    "provider" "SocialProvider" NOT NULL,
    "userId" BIGINT NOT NULL,

    CONSTRAINT "SocialLogin_pkey" PRIMARY KEY ("userId","provider")
);

-- AddForeignKey
ALTER TABLE "SocialLogin" ADD CONSTRAINT "SocialLogin_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
