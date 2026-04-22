import { redirect } from "next/navigation";

import { auth, signOut } from "~/auth";
import { DashboardClient } from "~/components/safenet/dashboard-client";
import { Button } from "~/components/ui/button";
import { isAdminUser } from "~/server/authz";

export default async function DashboardPage() {
  const session = await auth();

  if (!session?.user?.id) {
    redirect("/auth/login");
  }

  const isAdmin = isAdminUser(session.user.email);

  return (
    <main className="min-h-screen bg-[#09090B] text-[#F8FAFC]">
      <div className="mx-auto flex w-full max-w-7xl items-center justify-between border-b border-white/10 bg-gradient-to-r from-[#0F1117]/50 to-transparent px-4 py-5 md:px-8">
        <div className="space-y-1">
          <p className="text-xs uppercase tracking-[0.25em] text-[#06B6D4]">Threat Intelligence Console</p>
          <h1 className="font-heading text-2xl font-bold">SafeNet AI Command Center</h1>
          <p className="text-sm text-[#CBD5E1]">
            Detect, educate, and respond with enterprise-grade threat defense workflows.
          </p>
        </div>
        <form
          action={async () => {
            "use server";
            await signOut({ redirectTo: "/auth/login" });
          }}
        >
          <Button type="submit" className="border border-white/20 bg-transparent hover:bg-white/10">
            Sign out
          </Button>
        </form>
      </div>
      <DashboardClient
        userName={session.user.name ?? "SafeNet User"}
        userEmail={session.user.email ?? "Unknown"}
        isAdmin={isAdmin}
      />
    </main>
  );
}
