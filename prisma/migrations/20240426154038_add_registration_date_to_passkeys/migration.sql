/*
  Warnings:

  - Added the required column `registeredAt` to the `Passkey` table without a default value. This is not possible if the table is not empty.

*/
-- AlterTable
ALTER TABLE "Passkey" ADD COLUMN     "registeredAt" TIMESTAMP(3) NOT NULL;
