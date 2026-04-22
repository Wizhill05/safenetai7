import { TRPCError } from "@trpc/server";
import { z } from "zod";

import { env } from "~/env";
import { extractKeywords, mapRiskStatus } from "~/lib/security";
import { createTRPCRouter, protectedProcedure, publicProcedure } from "~/server/api/trpc";

const base64FileSchema = z.object({
  fileName: z.string().min(1),
  mimeType: z.string().min(1),
  base64Data: z.string().min(1),
});

function parseDomain(value: string): string {
  try {
    if (value.startsWith("http://") || value.startsWith("https://")) {
      return new URL(value).hostname;
    }
    return new URL(`https://${value}`).hostname;
  } catch {
    return value;
  }
}

function toRiskScoreByPrediction(prediction: string, confidence: number): number {
  const normalized = prediction.toLowerCase();
  if (normalized.includes("phishing") || normalized.includes("fake")) {
    return Math.min(100, Math.round(confidence * 100));
  }
  return Math.max(0, Math.round((1 - confidence) * 50));
}

async function safeJson(res: Response) {
  try {
    return await res.json();
  } catch {
    return null;
  }
}

export const scanRouter = createTRPCRouter({
  scanLink: publicProcedure
    .input(z.object({ url: z.string().url() }))
    .mutation(async ({ ctx, input }) => {
      const response = await fetch(`${env.BACKEND_API_URL}/scan/link/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: input.url }),
      });

      const payload = await safeJson(response);
      if (!response.ok || !payload) {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: "Link scanner backend is unavailable.",
        });
      }

      const confidence = Number(payload.confidence ?? 0);
      const riskScore = toRiskScoreByPrediction(String(payload.prediction ?? ""), confidence);
      const status = mapRiskStatus(riskScore);
      const keywords = extractKeywords(input.url);

      const userId = ctx.session?.user?.id;
      if (userId) {
        await ctx.db.scan.create({
          data: {
            type: "link",
            status,
            inputUrl: input.url,
            confidence,
            riskScore,
            keywords,
            explanation: `Prediction: ${payload.prediction}`,
            rawResponse: payload,
            userId,
          },
        });
      }

      return {
        prediction: payload.prediction as string,
        confidence,
        riskScore,
        status,
        keywords,
      };
    }),

  checkDomainAge: publicProcedure
    .input(z.object({ domain: z.string().min(1) }))
    .mutation(async ({ ctx, input }) => {
      const domain = parseDomain(input.domain);
      const url = `https://api.ip2whois.com/v2?key=${env.IP2WHOIS_API_KEY}&domain=${domain}`;
      const response = await fetch(url);
      const payload = await safeJson(response);

      if (!response.ok || !payload) {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: "Domain age API is unavailable.",
        });
      }

      const createDateRaw =
        String(payload.create_date ?? payload.creation_date ?? payload.created ?? "").trim();
      const createdAt = createDateRaw ? new Date(createDateRaw) : null;
      const now = Date.now();
      const ageYears =
        createdAt && !Number.isNaN(createdAt.getTime())
          ? Math.max(0, (now - createdAt.getTime()) / (1000 * 60 * 60 * 24 * 365.25))
          : null;

      const riskScore =
        ageYears === null
          ? 50
          : ageYears < 0.5
            ? 90
            : ageYears < 1
              ? 75
              : ageYears < 2
                ? 55
                : 20;

      const status = mapRiskStatus(riskScore);
      const userId = ctx.session?.user?.id;

      if (userId) {
        await ctx.db.scan.create({
          data: {
            type: "domain",
            status,
            inputDomain: domain,
            riskScore,
            explanation: ageYears
              ? `Domain age is ${ageYears.toFixed(2)} years.`
              : "Could not determine domain age.",
            rawResponse: payload,
            userId,
          },
        });
      }

      return {
        domain,
        createdAt: createdAt?.toISOString() ?? null,
        ageYears,
        riskScore,
        status,
        raw: payload,
      };
    }),

  scanEmail: publicProcedure
    .input(
      z.object({
        emailText: z.string().min(10),
        senderDomain: z.string().min(1).optional(),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      const senderDomain = parseDomain(input.senderDomain ?? "unknown.com");

      const response = await fetch(`${env.BACKEND_API_URL}/scan/email/`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text_content: input.emailText,
          sender_domain: senderDomain,
        }),
      });

      const payload = await safeJson(response);
      if (!response.ok || !payload) {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: "Email scanner backend is unavailable.",
        });
      }

      const confidence = Number(payload.confidence ?? 0);
      const riskScore = toRiskScoreByPrediction(String(payload.prediction ?? ""), confidence);
      const status = mapRiskStatus(riskScore);
      const keywords = extractKeywords(input.emailText);

      const explanation =
        status === "dangerous"
          ? "Email content matches known phishing patterns and urgency language."
          : status === "suspicious"
            ? "Email has mixed signals. Verify sender identity and links before acting."
            : "No major phishing patterns detected from this model response.";

      const userId = ctx.session?.user?.id;
      if (userId) {
        await ctx.db.scan.create({
          data: {
            type: "email",
            status,
            inputText: input.emailText,
            inputDomain: senderDomain,
            confidence,
            riskScore,
            keywords,
            explanation,
            rawResponse: payload,
            userId,
          },
        });
      }

      return {
        prediction: payload.prediction as string,
        confidence,
        riskScore,
        status,
        keywords,
        explanation,
      };
    }),

  scanDocument: publicProcedure
    .input(base64FileSchema)
    .mutation(async ({ ctx, input }) => {
      const base64 = input.base64Data.includes(",")
        ? input.base64Data.split(",")[1]
        : input.base64Data;

      if (!base64) {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Invalid file data." });
      }

      const bytes = Buffer.from(base64, "base64");
      const formData = new FormData();
      const blob = new Blob([bytes], { type: input.mimeType });
      formData.append("file", blob, input.fileName);

      const response = await fetch(`${env.BACKEND_API_URL}/scan/doc/`, {
        method: "POST",
        body: formData,
      });

      const payload = await safeJson(response);
      if (!response.ok || !payload) {
        throw new TRPCError({
          code: "BAD_REQUEST",
          message: "Document scanner backend is unavailable.",
        });
      }

      const riskScore = Number(payload.risk_score ?? 0);
      const status = mapRiskStatus(riskScore);
      const confidence = Number(payload.confidence ?? 0);
      const warnings = Array.isArray(payload.warnings) ? payload.warnings : [];

      const userId = ctx.session?.user?.id;
      if (userId) {
        await ctx.db.scan.create({
          data: {
            type: "document",
            status,
            inputText: input.fileName,
            confidence,
            riskScore,
            keywords: warnings,
            explanation: String(payload.verdict ?? "No explanation available."),
            rawResponse: payload,
            userId,
          },
        });
      }

      return {
        prediction: payload.prediction as string,
        confidence,
        riskScore,
        status,
        warnings,
        verdict: payload.verdict as string,
        indicators: payload.indicators ?? {},
      };
    }),

  history: protectedProcedure.query(async ({ ctx }) => {
    const scans = await ctx.db.scan.findMany({
      where: { userId: ctx.session.user.id },
      orderBy: { createdAt: "desc" },
      take: 50,
    });

    return scans;
  }),
});
