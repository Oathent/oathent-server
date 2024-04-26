-- AlterEnum
ALTER TYPE "MFAMethod" ADD VALUE 'WEB_AUTHN';

-- AlterTable
ALTER TABLE "MFADetail" ALTER COLUMN "secret" DROP NOT NULL;

-- CreateTable
CREATE TABLE "Passkey" (
    "id" TEXT NOT NULL,
    "publicKey" BYTEA NOT NULL,
    "counter" BIGINT NOT NULL,
    "mfaDetailUserId" BIGINT NOT NULL,
    "mfaDetailMethod" "MFAMethod" NOT NULL,

    CONSTRAINT "Passkey_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "Passkey" ADD CONSTRAINT "Passkey_mfaDetailUserId_mfaDetailMethod_fkey" FOREIGN KEY ("mfaDetailUserId", "mfaDetailMethod") REFERENCES "MFADetail"("userId", "method") ON DELETE RESTRICT ON UPDATE CASCADE;
