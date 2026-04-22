import { TRPCError } from "@trpc/server";
import { z } from "zod";
import { createTRPCRouter, protectedProcedure, publicProcedure } from "~/server/api/trpc";

const reportTypeSchema = z.enum(["link", "email", "document", "other"]);

const createReportSchema = z.object({
  title: z.string().min(3).max(140),
  type: reportTypeSchema,
  description: z.string().min(10).max(5000),
  url: z.string().url().optional().or(z.literal("")),
  email: z.string().email().optional().or(z.literal("")),
  reporterInfo: z.string().max(500).optional(),
  proofFile: z
    .object({
      fileName: z.string().min(1),
      mimeType: z.string().min(1),
      base64Data: z.string().min(1),
      sizeBytes: z.number().int().min(1),
    })
    .optional(),
});
///

export const reportRouter = createTRPCRouter({
  submit: publicProcedure
    .input(createReportSchema)
    .mutation(async ({ ctx, input }) => {
      const userId = ctx.session?.user?.id;

      const report = await ctx.db.report.create({
        data: {
          title: input.title,
          type: input.type,
          description: input.description,
          url: input.url ?? null,
          email: input.email ?? null,
          reporterInfo: input.reporterInfo ?? null,
          status: "pending",
          userId,
        },
      });

      if (input.proofFile) {
        await ctx.db.fileUpload.create({
          data: {
            fileName: input.proofFile.fileName,
            mimeType: input.proofFile.mimeType,
            sizeBytes: input.proofFile.sizeBytes,
            base64Data: input.proofFile.base64Data,
            reportId: report.id,
            userId,
          },
        });
      }

      return {
        id: report.id,
        status: report.status,
      };
    }),

  reportFeed: publicProcedure.query(async ({ ctx }) => {
    const reports = await ctx.db.report.findMany({
      orderBy: { createdAt: "desc" },
      take: 100,
      include: {
        uploads: {
          select: {
            id: true,
            fileName: true,
            mimeType: true,
            sizeBytes: true,
            base64Data: true,
            createdAt: true,
          },
        },
        user: {
          select: {
            id: true,
            name: true,
            email: true,
          },
        },
      },
    });

    return reports;
  }),

  myReports: protectedProcedure.query(async ({ ctx }) => {
    return ctx.db.report.findMany({
      where: { userId: ctx.session.user.id },
      orderBy: { createdAt: "desc" },
      take: 50,
      include: {
        uploads: {
          select: {
            id: true,
            fileName: true,
            mimeType: true,
            sizeBytes: true,
            createdAt: true,
          },
        },
      },
    });
  }),

  dashboardSummary: protectedProcedure.query(async ({ ctx }) => {
    const userId = ctx.session.user.id;

    const [totalScans, dangerousScans, totalReports, recentScans] = await Promise.all([
      ctx.db.scan.count({ where: { userId } }),
      ctx.db.scan.count({ where: { userId, status: "dangerous" } }),
      ctx.db.report.count(),
      ctx.db.scan.findMany({
        where: { userId },
        orderBy: { createdAt: "desc" },
        take: 8,
      }),
    ]);

    if (Number.isNaN(totalScans)) {
      throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "Summary failed." });
    }

    return {
      totalScans,
      dangerousScans,
      totalReports,
      recentScans,
    };
  }),
});
