import { hash } from "bcryptjs";
import { TRPCError } from "@trpc/server";
import { z } from "zod";

import { createTRPCRouter, protectedProcedure, publicProcedure } from "~/server/api/trpc";

export const authRouter = createTRPCRouter({
  register: publicProcedure
    .input(
      z.object({
        name: z.string().min(2).max(80).optional(),
        email: z.string().email(),
        password: z.string().min(6).max(64),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      const existing = await ctx.db.user.findUnique({
        where: { email: input.email.toLowerCase() },
      });

      if (existing) {
        throw new TRPCError({
          code: "CONFLICT",
          message: "Email already in use.",
        });
      }

      const passwordHash = await hash(input.password, 12);

      const user = await ctx.db.user.create({
        data: {
          email: input.email.toLowerCase(),
          name: input.name,
          passwordHash,
        },
        select: {
          id: true,
          email: true,
          name: true,
        },
      });

      return user;
    }),

  me: protectedProcedure.query(async ({ ctx }) => {
    const userId = ctx.session.user.id;

    const user = await ctx.db.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        name: true,
        createdAt: true,
      },
    });

    if (!user) {
      throw new TRPCError({ code: "NOT_FOUND", message: "User not found." });
    }

    return user;
  }),
});
