-- DropForeignKey
ALTER TABLE "Passkey" DROP CONSTRAINT "Passkey_mfaDetailUserId_mfaDetailMethod_fkey";

-- AddForeignKey
ALTER TABLE "Passkey" ADD CONSTRAINT "Passkey_mfaDetailUserId_mfaDetailMethod_fkey" FOREIGN KEY ("mfaDetailUserId", "mfaDetailMethod") REFERENCES "MFADetail"("userId", "method") ON DELETE CASCADE ON UPDATE CASCADE;
