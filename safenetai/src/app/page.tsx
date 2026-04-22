import Link from "next/link";
import { AlertTriangle, BookOpen, ShieldCheck, Zap } from "lucide-react";
import { type ReactNode } from "react";

import { auth } from "~/auth";
import { Button } from "~/components/ui/button";

export default async function Home() {
  const session = await auth();

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#09090B] px-4 py-12 text-[#F8FAFC] md:px-8">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_15%_10%,rgba(124,58,237,0.25),transparent_35%),radial-gradient(circle_at_90%_15%,rgba(6,182,212,0.15),transparent_30%),radial-gradient(circle_at_50%_105%,rgba(16,185,129,0.1),transparent_40%)]" />
      <div className="relative mx-auto flex w-full max-w-7xl flex-col gap-6">
        <section className="rounded-3xl border border-white/10 bg-gradient-to-br from-[#0F1117] via-[#09090B] to-[#0F1117] p-8 backdrop-blur-xl md:p-12">
          <p className="mb-4 text-xs uppercase tracking-[0.3em] text-[#06B6D4]">Enterprise Cyber Threat Defense</p>
          <h1 className="font-heading text-4xl leading-tight md:text-7xl">
            SafeNet AI
            <span className="block text-[#7C3AED]">Threat Intelligence for Modern Communities</span>
          </h1>
          <p className="mt-6 max-w-3xl text-base text-[#CBD5E1] md:text-lg">
            Advanced threat detection, community intelligence, and rapid response workflows.
            Enterprise-grade security architecture built for startup agility.
          </p>

          <div className="mt-8 flex flex-wrap gap-3">
            {session?.user?.id ? (
              <Link href="/dashboard">
                <Button className="bg-[#7C3AED] px-6 text-white hover:bg-[#7C3AED]/80 shadow-lg shadow-purple-500/20">
                  Launch Command Center
                </Button>
              </Link>
            ) : (
              <>
                <Link href="/auth/login">
                  <Button className="bg-[#7C3AED] px-6 text-white hover:bg-[#7C3AED]/80 shadow-lg shadow-purple-500/20">
                    Sign In
                  </Button>
                </Link>
                <Link href="/auth/signup">
                  <Button className="bg-[#10B981] px-6 text-[#09090B] hover:bg-[#10B981]/80 shadow-lg shadow-emerald-500/20">
                    Create Account
                  </Button>
                </Link>
              </>
            )}
          </div>

          <div className="mt-8 grid gap-3 md:grid-cols-4">
            <FeatureBadge icon={<ShieldCheck className="size-4 text-[#06B6D4]" />} text="Link & Domain Detection" />
            <FeatureBadge icon={<Zap className="size-4 text-[#7C3AED]" />} text="Real-time Risk Scoring" />
            <FeatureBadge icon={<BookOpen className="size-4 text-[#10B981]" />} text="Security Education Hub" />
            <FeatureBadge icon={<AlertTriangle className="size-4 text-[#EC4899]" />} text="Community Threat Feed" />
          </div>
        </section>

        <section className="grid gap-4 md:grid-cols-3">
          <InfoCard
            title="Detection Engine"
            description="Real-time risk scoring for links, domains, emails, and documents via enterprise Python APIs."
            accent="from-purple-500/10"
          />
          <InfoCard
            title="Intelligence Layer"
            description="Community reporting keeps threat intelligence flowing into the public feed."
            accent="from-cyan-500/10"
          />
          <InfoCard
            title="Education & Response"
            description="Comprehensive security awareness combined with rapid admin response workflows for community protection."
            accent="from-emerald-500/10"
          />
        </section>

        <section className="rounded-2xl border border-[#7C3AED]/30 bg-gradient-to-r from-[#7C3AED]/5 to-[#06B6D4]/5 p-6">
          <h2 className="font-heading text-2xl">Enterprise-Ready Platform</h2>
          <p className="mt-2 max-w-4xl text-[#CBD5E1]">
            Detect advanced threats, provide instant explanations, surface community intelligence, and educate users—all within
            a secure, professional platform. SafeNet AI delivers startup innovation with enterprise security standards.
          </p>
        </section>
      </div>
    </main>
  );
}

function FeatureBadge({ icon, text }: { icon: ReactNode; text: string }) {
  return (
    <div className="flex items-center gap-2 rounded-xl border border-white/10 bg-[#0F1117]/60 px-3 py-2 text-sm text-[#CBD5E1] backdrop-blur-md hover:border-[#7C3AED]/30 hover:bg-[#0F1117] transition-all">
      {icon}
      <span>{text}</span>
    </div>
  );
}

function InfoCard({ title, description, accent }: { title: string; description: string; accent: string }) {
  return (
    <div className={`rounded-2xl border border-white/10 bg-gradient-to-br ${accent} to-transparent p-4 backdrop-blur-xl hover:border-white/20 transition-all`}>
      <h3 className="mb-1 font-semibold text-[#F8FAFC]">{title}</h3>
      <p className="text-sm text-[#CBD5E1]">{description}</p>
    </div>
  );
}
