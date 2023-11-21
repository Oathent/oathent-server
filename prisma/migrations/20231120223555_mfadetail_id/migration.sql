-- DropIndex
DROP INDEX "MFADetail_userId_method_key";

-- AlterTable
ALTER TABLE "MFADetail" ADD CONSTRAINT "MFADetail_pkey" PRIMARY KEY ("userId", "method");
