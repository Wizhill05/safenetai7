import { PrismaClient } from "../generated/prisma/index.js";
import { hash } from "bcryptjs";

const prisma = new PrismaClient();

async function main() {
  const existingSeedData = await prisma.report.count({
    where: { title: { startsWith: "[Seed]" } },
  });

  if (existingSeedData > 0) {
    console.log("Seed data already exists. Skipping.");
    return;
  }

  const adminPassword = await hash("Admin@123", 12);
  const userPassword = await hash("User@123", 12);

  const admin = await prisma.user.upsert({
    where: { email: "admin@safenet.ai" },
    update: {},
    create: {
      name: "SafeNet Admin",
      email: "admin@safenet.ai",
      passwordHash: adminPassword,
    },
  });

  const userA = await prisma.user.upsert({
    where: { email: "maya.demo@safenet.ai" },
    update: {},
    create: {
      name: "Maya Verma",
      email: "maya.demo@safenet.ai",
      passwordHash: userPassword,
    },
  });

  const userB = await prisma.user.upsert({
    where: { email: "arun.demo@safenet.ai" },
    update: {},
    create: {
      name: "Arun Iyer",
      email: "arun.demo@safenet.ai",
      passwordHash: userPassword,
    },
  });

  await prisma.scan.createMany({
    data: [
      {
        userId: userA.id,
        type: "link",
        inputUrl:
          "https://paytm-security-alerts.example-login-check.com/verify-wallet",
        rawResponse: {
          source: "ml-backend",
          label: "phishing",
          indicators: [
            "lookalike-domain",
            "credential-harvest-pattern",
            "suspicious-tld",
          ],
          confidence: 0.93,
        },
        confidence: 0.93,
        riskScore: 92,
        explanation: "Detected as high-risk phishing URL with lookalike-domain signals.",
        keywords: ["otp", "wallet", "login"],
        status: "dangerous",
      },
      {
        userId: userA.id,
        type: "email",
        inputText: "Subject: urgent invoice correction needed",
        rawResponse: {
          source: "ml-backend",
          label: "suspicious",
          indicators: ["urgency-language", "spoofed-display-name"],
          confidence: 0.81,
        },
        confidence: 0.81,
        riskScore: 68,
        explanation: "Urgent language and sender mismatch indicate a likely scam attempt.",
        keywords: ["invoice", "urgent", "reply-to"],
        status: "suspicious",
      },
      {
        userId: userB.id,
        type: "domain",
        inputDomain: "secure-kbank-verification.co",
        rawResponse: {
          source: "ip2whois",
          domainAgeDays: 12,
          registrarRisk: "high",
          confidence: 0.88,
        },
        confidence: 0.88,
        riskScore: 89,
        explanation: "Newly registered domain with brand-like name has high abuse probability.",
        keywords: ["domain-age", "lookalike", "brand-abuse"],
        status: "dangerous",
      },
      {
        userId: userB.id,
        type: "document",
        inputText: "loan-approval-form.pdf",
        rawResponse: {
          source: "ml-backend",
          label: "safe",
          indicators: ["no-malicious-macros", "trusted-layout"],
          confidence: 0.9,
        },
        confidence: 0.9,
        riskScore: 18,
        explanation: "No malicious markers were detected in the uploaded sample document.",
        keywords: ["pdf", "loan", "document"],
        status: "safe",
      },
    ],
  });

  const approvedReport = await prisma.report.create({
    data: {
      userId: userA.id,
      type: "link",
      title: "[Seed] Fake wallet reactivation page",
      description:
        "Victims are asked to re-login and provide OTP to reactivate wallet access.",
      url:
        "https://wallet-reactivate-secure-check.example.com/auth/verify",
      reporterInfo: "Community Watch Volunteer",
      status: "approved",
      approvedAt: new Date(),
      moderationVerdict: "approve",
      moderationReason:
        "Approved for community visibility. High relevance and clear indicators.",
      moderationConfidence: 0.92,
      moderationRaw: {
        model: "gemini-2.5-flash",
        action: "approve",
        confidence: 0.92,
      },
    },
  });

  const pendingReport = await prisma.report.create({
    data: {
      userId: userB.id,
      type: "email",
      title: "[Seed] Payroll correction attachment",
      description:
        "Email claims salary account is frozen and asks to open an attachment.",
      email:
        "Sender used HR display name but mismatched domain in the reply-to header.",
      reporterInfo: "Anonymous",
      status: "pending",
    },
  });

  await prisma.report.create({
    data: {
      userId: admin.id,
      type: "other",
      title: "[Seed] Crypto giveaway impersonation",
      description:
        "Social media account impersonates a known founder and posts giveaway links.",
      url:
        "Profile copied branding and redirected users to a fake exchange onboarding form.",
      reporterInfo: "Platform Moderator",
      status: "rejected",
      moderationVerdict: "reject",
      moderationReason: "Rejected due to insufficient evidence attachment in this report.",
      moderationConfidence: 0.74,
      moderationRaw: {
        model: "gemini-2.5-flash",
        action: "reject",
        confidence: 0.74,
      },
    },
  });

  await prisma.fileUpload.createMany({
    data: [
      {
        userId: userA.id,
        reportId: approvedReport.id,
        fileName: "screenshot-wallet-alert.png",
        mimeType: "image/png",
        sizeBytes: 244312,
        base64Data: "c2FmZW5ldC1zZWVkLWltYWdlLWRhdGE=",
      },
      {
        userId: userB.id,
        reportId: pendingReport.id,
        fileName: "payroll-mail.eml",
        mimeType: "message/rfc822",
        sizeBytes: 98312,
        base64Data: "c2FmZW5ldC1zZWVkLWVtbC1kYXRh",
      },
    ],
  });

  const [userCount, scanCount, reportCount, uploadCount] = await Promise.all([
    prisma.user.count(),
    prisma.scan.count(),
    prisma.report.count(),
    prisma.fileUpload.count(),
  ]);

  console.log("Seed completed.");
  console.log({ userCount, scanCount, reportCount, uploadCount });
}

main()
  .catch((error) => {
    console.error("Seed failed:", error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
