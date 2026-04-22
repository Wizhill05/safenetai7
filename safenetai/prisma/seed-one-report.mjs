import { PrismaClient } from "../generated/prisma/index.js";

const prisma = new PrismaClient();

async function main() {
  const existing = await prisma.report.findFirst({
    where: { title: "[Seed Extra] UPI KYC scam with screenshot" },
    select: { id: true },
  });

  if (existing) {
    console.log("Report already exists. Skipping.", { reportId: existing.id });
    return;
  }

  let user = await prisma.user.findFirst({
    where: { email: "maya.demo@safenet.ai" },
    select: { id: true },
  });

  if (!user) {
    user = await prisma.user.findFirst({ select: { id: true } });
  }

  const report = await prisma.report.create({
    data: {
      userId: user?.id ?? null,
      type: "link",
      title: "[Seed Extra] UPI KYC scam with screenshot",
      description:
        "Scammer asks users to complete urgent UPI KYC and share OTP via a fake support portal.",
      url: "https://secure-upi-kyc-check.example.com/verify",
      reporterInfo: "Student Safety Club",
      status: "approved",
      approvedAt: new Date(),
      moderationVerdict: "APPROVED",
      moderationReason:
        "High-confidence phishing indicators and clear social engineering pattern.",
      moderationConfidence: 0.94,
      moderationRaw: {
        model: "gemini-2.5-flash",
        action: "approve",
        confidence: 0.94,
      },
    },
    select: { id: true },
  });

  const oneByOnePngBase64 =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9pA5xD4AAAAASUVORK5CYII=";

  const upload = await prisma.fileUpload.create({
    data: {
      userId: user?.id ?? null,
      reportId: report.id,
      fileName: "upi-kyc-scam-screenshot.png",
      mimeType: "image/png",
      sizeBytes: 68,
      base64Data: oneByOnePngBase64,
    },
    select: { id: true },
  });

  console.log("Seeded one approved report with screenshot.", {
    reportId: report.id,
    uploadId: upload.id,
  });
}

main()
  .catch((error) => {
    console.error("Seed one report failed:", error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
