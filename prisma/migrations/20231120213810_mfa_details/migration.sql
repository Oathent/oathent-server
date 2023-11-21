/*
  Warnings:

  - You are about to drop the column `mfaMethod` on the `User` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "User" DROP COLUMN "mfaMethod";

-- CreateTable
CREATE TABLE "MFADetail" (
    "userId" BIGINT NOT NULL,
    "method" "MFAMethod" NOT NULL,
    "secret" TEXT NOT NULL
);

-- CreateIndex
CREATE UNIQUE INDEX "MFADetail_userId_method_key" ON "MFADetail"("userId", "method");

-- AddForeignKey
ALTER TABLE "MFADetail" ADD CONSTRAINT "MFADetail_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
