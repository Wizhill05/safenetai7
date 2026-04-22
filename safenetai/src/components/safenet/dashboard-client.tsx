"use client";

import {
  AlertTriangle,
  BookOpen,
  Bot,
  FileText,
  Link2,
  Mail,
  MessageSquare,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import Image from "next/image";
import { type ReactNode, useMemo, useState } from "react";

import { StatusBadge } from "~/components/safenet/status-badge";
import { Button } from "~/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "~/components/ui/card";
import { Input } from "~/components/ui/input";
import { Textarea } from "~/components/ui/textarea";
import { api } from "~/trpc/react";

async function fileToBase64(file: File): Promise<string> {
  return await new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result;
      if (typeof result === "string") {
        resolve(result);
        return;
      }

      reject(new Error("Could not convert file to base64 string."));
    };
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

type DashboardClientProps = {
  userName: string;
  userEmail: string;
  isAdmin: boolean;
};

type Section = "detect" | "impact" | "reports" | "edu" | "admin";

function bytesToLabel(sizeBytes: number): string {
  if (sizeBytes < 1024) return `${sizeBytes} B`;
  if (sizeBytes < 1024 * 1024) return `${(sizeBytes / 1024).toFixed(1)} KB`;
  return `${(sizeBytes / (1024 * 1024)).toFixed(1)} MB`;
}

function fileToDataUrl(mimeType: string, base64Data: string): string {
  if (base64Data.startsWith("data:")) {
    return base64Data;
  }
  return `data:${mimeType};base64,${base64Data}`;
}

export function DashboardClient({ userName, userEmail, isAdmin }: DashboardClientProps) {
  const [activeSection, setActiveSection] = useState<Section>("detect");

  const [linkUrl, setLinkUrl] = useState("");
  const [domainValue, setDomainValue] = useState("");
  const [emailText, setEmailText] = useState("");
  const [senderDomain, setSenderDomain] = useState("");
  const [documentFile, setDocumentFile] = useState<File | null>(null);

  const [reportTitle, setReportTitle] = useState("");
  const [reportType, setReportType] = useState<"link" | "email" | "document" | "other">("link");
  const [reportDescription, setReportDescription] = useState("");
  const [reportUrl, setReportUrl] = useState("");
  const [reportEmail, setReportEmail] = useState("");
  const [reporterInfo, setReporterInfo] = useState("");
  const [proofFile, setProofFile] = useState<File | null>(null);

  const [moderationReason, setModerationReason] = useState("Verified indicators and community evidence");
  const [chatInput, setChatInput] = useState("");
  const [chatLog, setChatLog] = useState<Array<{ role: "user" | "assistant"; text: string }>>([
    {
      role: "assistant",
      text: "Support copilot online. Ask me to draft scam safety guidance or user-facing replies.",
    },
  ]);

  const summary = api.report.dashboardSummary.useQuery();
  const reportFeed = api.report.reportFeed.useQuery();
  const history = api.scan.history.useQuery();

  const adminOverview = api.admin.overview.useQuery(undefined, { enabled: isAdmin });
  const adminReports = api.admin.reviewReports.useQuery({ limit: 60 }, { enabled: isAdmin });

  const linkScan = api.scan.scanLink.useMutation({
    onSuccess: async () => {
      await Promise.all([summary.refetch(), history.refetch()]);
    },
  });
  const domainScan = api.scan.checkDomainAge.useMutation({
    onSuccess: async () => {
      await Promise.all([summary.refetch(), history.refetch()]);
    },
  });
  const emailScan = api.scan.scanEmail.useMutation({
    onSuccess: async () => {
      await Promise.all([summary.refetch(), history.refetch()]);
    },
  });
  const docScan = api.scan.scanDocument.useMutation({
    onSuccess: async () => {
      await Promise.all([summary.refetch(), history.refetch()]);
    },
  });

  const reportSubmit = api.report.submit.useMutation({
    onSuccess: async () => {
      if (isAdmin) {
        await Promise.all([summary.refetch(), reportFeed.refetch(), adminReports.refetch()]);
      } else {
        await Promise.all([summary.refetch(), reportFeed.refetch()]);
      }
      setReportTitle("");
      setReportDescription("");
      setReportUrl("");
      setReportEmail("");
      setReporterInfo("");
      setProofFile(null);
    },
  });

  const adminUpdate = api.admin.updateReportStatus.useMutation({
    onSuccess: async () => {
      if (isAdmin) {
        await Promise.all([adminReports.refetch(), reportFeed.refetch(), adminOverview.refetch()]);
      } else {
        await reportFeed.refetch();
      }
    },
  });

  const supportReply = api.admin.supportReply.useMutation();

  const stats = useMemo(() => {
    const reportsByType = adminOverview.data?.reportsByType ?? [];

    return {
      totalScans: summary.data?.totalScans ?? 0,
      dangerousScans: summary.data?.dangerousScans ?? 0,
      totalReports: summary.data?.totalReports ?? 0,
      reportsByType,
      totalDetectedGlobal: adminOverview.data?.totalScans ?? 0,
      userReportsGlobal: adminOverview.data?.totalReports ?? 0,
    };
  }, [summary.data, adminOverview.data]);

  const navItems: Array<{ key: Section; label: string }> = [
    { key: "detect", label: "Detection Lab" },
    { key: "impact", label: "Impact Board" },
    { key: "reports", label: "Community Reports" },
    { key: "edu", label: "Edu Hub" },
  ];

  if (isAdmin) {
    navItems.push({ key: "admin", label: "Admin Studio" });
  }

  return (
    <div className="mx-auto flex w-full max-w-7xl flex-col gap-6 px-4 py-8 md:px-8">
      <section className="rounded-3xl border border-white/15 bg-gradient-to-r from-[#0F1117]/50 to-transparent p-5 backdrop-blur-xl md:p-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <p className="text-xs uppercase tracking-[0.25em] text-[#06B6D4]">Enterprise Defense</p>
            <h2 className="font-heading text-2xl">ThreatOps + TrustOps + EduOps</h2>
            <p className="text-sm text-[#CBD5E1]">
              Build trust by combining real-time defense, public awareness, and moderated reporting.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            {navItems.map((item) => (
              <button
                key={item.key}
                onClick={() => setActiveSection(item.key)}
                className={`rounded-full border px-4 py-1.5 text-sm transition ${
                  activeSection === item.key
                    ? "border-[#7C3AED] bg-[#7C3AED]/25 text-[#F8FAFC]"
                    : "border-white/15 bg-transparent text-[#CBD5E1] hover:border-[#7C3AED]/50"
                }`}
              >
                {item.label}
              </button>
            ))}
          </div>
        </div>
      </section>

      <section className="grid gap-4 md:grid-cols-4">
        <MetricCard title="Scams Detected" value={stats.totalDetectedGlobal} color="text-[#7C3AED]" />
        <MetricCard title="High Risk Flags" value={stats.dangerousScans} color="text-[#EC4899]" />
        <MetricCard title="User Reports" value={stats.userReportsGlobal} color="text-[#F59E0B]" />
        <MetricCard title="Community Reports" value={stats.totalReports} color="text-[#10B981]" />
      </section>

      {activeSection === "detect" && (
        <section className="grid gap-4 xl:grid-cols-2">
          <ScanCard
            icon={<Link2 className="size-4" />}
            title="Link Scanner"
            description="Risk score, keyword extraction, and clear status labeling"
          >
            <Input value={linkUrl} onChange={(e) => setLinkUrl(e.target.value)} placeholder="https://suspicious.site/login" />
            <Button className="w-full bg-[#7C3AED] text-white hover:bg-[#7C3AED]/80" onClick={() => linkScan.mutate({ url: linkUrl })} disabled={linkScan.isPending || !linkUrl}>
              {linkScan.isPending ? "Scanning..." : "Scan Link"}
            </Button>
            {linkScan.data && (
              <ResultPanel>
                <div className="mb-2 flex items-center justify-between">
                  <p className="font-medium">Risk Score: {linkScan.data.riskScore}</p>
                  <StatusBadge status={linkScan.data.status} />
                </div>
                <p className="text-sm text-[#F8FAFC]/70">Keywords: {linkScan.data.keywords.join(", ") || "None"}</p>
              </ResultPanel>
            )}
          </ScanCard>

          <ScanCard
            icon={<ShieldCheck className="size-4" />}
            title="Domain Age Checker"
            description="Detect risky newly-created domains using IP2WHOIS"
          >
            <Input value={domainValue} onChange={(e) => setDomainValue(e.target.value)} placeholder="domain.com" />
            <Button className="w-full bg-[#7C3AED] text-white hover:bg-[#7C3AED]/80" onClick={() => domainScan.mutate({ domain: domainValue })} disabled={domainScan.isPending || !domainValue}>
              {domainScan.isPending ? "Checking..." : "Check Domain"}
            </Button>
            {domainScan.data && (
              <ResultPanel>
                <div className="mb-2 flex items-center justify-between">
                  <p className="font-medium">{domainScan.data.domain}</p>
                  <StatusBadge status={domainScan.data.status} />
                </div>
                <p className="text-sm text-[#F8FAFC]/70">Created: {domainScan.data.createdAt ? new Date(domainScan.data.createdAt).toLocaleDateString() : "Unknown"}</p>
                <p className="text-sm text-[#F8FAFC]/70">Age: {domainScan.data.ageYears ? `${domainScan.data.ageYears.toFixed(2)} years` : "Unknown"}</p>
              </ResultPanel>
            )}
          </ScanCard>

          <ScanCard
            icon={<Mail className="size-4" />}
            title="Email Scanner"
            description="Analyze suspicious text and explain risk patterns"
          >
            <Input value={senderDomain} onChange={(e) => setSenderDomain(e.target.value)} placeholder="sender-domain.com (optional)" />
            <Textarea value={emailText} onChange={(e) => setEmailText(e.target.value)} placeholder="Paste suspicious email content" />
            <Button className="w-full bg-[#7C3AED] text-white hover:bg-[#7C3AED]/80" onClick={() => emailScan.mutate({ emailText, senderDomain })} disabled={emailScan.isPending || emailText.length < 10}>
              {emailScan.isPending ? "Analyzing..." : "Scan Email"}
            </Button>
            {emailScan.data && (
              <ResultPanel>
                <div className="mb-2 flex items-center justify-between">
                  <p className="font-medium">Risk Score: {emailScan.data.riskScore}</p>
                  <StatusBadge status={emailScan.data.status} />
                </div>
                <p className="text-sm text-[#F8FAFC]/70">{emailScan.data.explanation}</p>
              </ResultPanel>
            )}
          </ScanCard>

          <ScanCard
            icon={<FileText className="size-4" />}
            title="Document Scanner"
            description="Upload evidence and detect phishing intent"
          >
            <Input type="file" accept=".pdf,.docx,.txt" onChange={(e) => setDocumentFile(e.target.files?.[0] ?? null)} />
            <Button
              className="w-full bg-[#7C3AED] text-white hover:bg-[#7C3AED]/80"
              disabled={!documentFile || docScan.isPending}
              onClick={async () => {
                if (!documentFile) return;
                const base64Data = await fileToBase64(documentFile);
                docScan.mutate({
                  fileName: documentFile.name,
                  mimeType: documentFile.type || "application/octet-stream",
                  base64Data,
                });
              }}
            >
              {docScan.isPending ? "Processing..." : "Scan Document"}
            </Button>
            {docScan.data && (
              <ResultPanel>
                <div className="mb-2 flex items-center justify-between">
                  <p className="font-medium">Risk Score: {docScan.data.riskScore}</p>
                  <StatusBadge status={docScan.data.status} />
                </div>
                <p className="text-sm text-[#F8FAFC]/70">{docScan.data.verdict}</p>
              </ResultPanel>
            )}
          </ScanCard>
        </section>
      )}

      {activeSection === "impact" && (
        <section className="grid gap-4 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><ShieldAlert className="size-4" /> Scam Type Distribution</CardTitle>
              <CardDescription>Types of scams surfaced by community scans and reports</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {stats.reportsByType.length === 0 && <p className="text-sm text-[#F8FAFC]/60">No report type data yet.</p>}
                {stats.reportsByType.map((item) => (
                  <div key={item.type} className="rounded-lg border border-white/10 bg-[#09090B]/50 p-3">
                    <div className="mb-1 flex items-center justify-between">
                      <p className="text-sm font-medium uppercase text-[#F8FAFC]">{item.type}</p>
                      <p className="text-sm font-semibold text-[#10B981]">{item._count._all}</p>
                    </div>
                    <div className="h-2 rounded-full bg-white/10">
                      <div
                        className="h-2 rounded-full bg-[#7C3AED]"
                        style={{ width: `${Math.min(100, item._count._all * 10)}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><Sparkles className="size-4" /> Your Latest Activity</CardTitle>
              <CardDescription>Personal timeline of security checks</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="max-h-96 space-y-2 overflow-y-auto pr-1">
                {(history.data ?? []).map((scan) => (
                  <div key={scan.id} className="flex items-center justify-between rounded-lg border border-white/10 bg-[#09090B]/60 p-2">
                    <div>
                      <p className="text-sm font-semibold uppercase">{scan.type}</p>
                      <p className="text-xs text-[#F8FAFC]/60">{new Date(scan.createdAt).toLocaleString()}</p>
                    </div>
                    <StatusBadge status={scan.status} />
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </section>
      )}

      {activeSection === "reports" && (
        <section className="grid gap-4 xl:grid-cols-5">
          <Card className="xl:col-span-3">
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><AlertTriangle className="size-4" /> Self-Reporting System</CardTitle>
              <CardDescription>
                Submit verified incidents. Reports appear immediately in the public feed.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Input value={reportTitle} onChange={(e) => setReportTitle(e.target.value)} placeholder="Title" />
              <select value={reportType} onChange={(e) => setReportType(e.target.value as "link" | "email" | "document" | "other")} className="h-10 w-full rounded-lg border border-white/15 bg-white/5 px-3 text-sm text-[#F8FAFC]">
                <option value="link">Link</option>
                <option value="email">Email</option>
                <option value="document">Document</option>
                <option value="other">Other</option>
              </select>
              <Textarea value={reportDescription} onChange={(e) => setReportDescription(e.target.value)} placeholder="Describe the scam pattern and evidence" />
              <div className="grid gap-3 md:grid-cols-2">
                <Input value={reportUrl} onChange={(e) => setReportUrl(e.target.value)} placeholder="URL (optional)" />
                <Input value={reportEmail} onChange={(e) => setReportEmail(e.target.value)} placeholder="Email (optional)" />
              </div>
              <Input value={reporterInfo} onChange={(e) => setReporterInfo(e.target.value)} placeholder="Reporter info (optional)" />
              <Input type="file" onChange={(e) => setProofFile(e.target.files?.[0] ?? null)} />
              <Button
                className="w-full bg-[#10B981] text-[#09090B] hover:bg-[#10B981]/80"
                disabled={reportSubmit.isPending || reportDescription.length < 10 || reportTitle.length < 3}
                onClick={async () => {
                  const proofData =
                    proofFile == null
                      ? undefined
                      : {
                          fileName: proofFile.name,
                          mimeType: proofFile.type || "application/octet-stream",
                          base64Data: await fileToBase64(proofFile),
                          sizeBytes: proofFile.size,
                        };

                  reportSubmit.mutate({
                    title: reportTitle,
                    type: reportType,
                    description: reportDescription,
                    url: reportUrl,
                    email: reportEmail,
                    reporterInfo,
                    proofFile: proofData,
                  });
                }}
              >
                {reportSubmit.isPending ? "Submitting..." : "Submit Report"}
              </Button>
              {reportSubmit.data && <p className="text-sm text-[#F8FAFC]/70">Report received. Status: {reportSubmit.data.status.toUpperCase()}.</p>}
            </CardContent>
          </Card>

          <Card className="xl:col-span-2">
            <CardHeader>
              <CardTitle>Community Reports</CardTitle>
              <CardDescription>Community-impact timeline</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {(reportFeed.data ?? []).map((item) => (
                  <div key={item.id} className="rounded-xl border border-white/10 bg-[#09090B]/60 p-3">
                    <div className="mb-1 flex items-center justify-between">
                      <p className="font-semibold">{item.title}</p>
                      <span className="rounded-full border border-[#10B981]/30 bg-[#10B981]/20 px-2 py-0.5 text-xs uppercase text-[#10B981]">{item.type}</span>
                    </div>
                    <p className="mb-2 text-xs text-[#F8FAFC]/50">
                      {new Date(item.createdAt).toLocaleString()} {item.user?.name ? `• by ${item.user.name}` : ""}
                    </p>
                    <p className="text-sm text-[#F8FAFC]/80 whitespace-pre-wrap">{item.description}</p>
                    {item.url && <p className="mt-2 text-sm text-[#93C5FD] break-all">Link: {item.url}</p>}
                    {item.email && <p className="mt-1 text-sm text-[#FCD34D] break-all">Email: {item.email}</p>}
                    {item.reporterInfo && <p className="mt-1 text-xs text-[#F8FAFC]/60">Reporter: {item.reporterInfo}</p>}

                    {item.uploads.length > 0 && (
                      <div className="mt-3 space-y-2 rounded-lg border border-white/10 bg-white/5 p-2">
                        <p className="text-xs uppercase tracking-wide text-[#10B981]">Attached Evidence</p>
                        {item.uploads.map((upload: { id: string; fileName: string; mimeType: string; sizeBytes: number; base64Data?: string | null }) => {
                          const safeBase64 = typeof upload.base64Data === "string" ? upload.base64Data : "";
                          const src = fileToDataUrl(upload.mimeType, safeBase64);
                          const isImage = upload.mimeType.startsWith("image/");

                          return (
                            <div key={upload.id} className="rounded-md border border-white/10 bg-[#09090B]/70 p-2">
                              <p className="text-xs text-[#F8FAFC]/70">
                                {upload.fileName} • {upload.mimeType} • {bytesToLabel(upload.sizeBytes)}
                              </p>
                              {isImage ? (
                                <Image
                                  src={src}
                                  alt={upload.fileName}
                                  width={1200}
                                  height={800}
                                  unoptimized
                                  className="mt-2 max-h-80 w-full rounded-md border border-white/10 object-contain"
                                />
                              ) : (
                                <a
                                  className="mt-2 inline-block text-xs text-[#93C5FD] underline"
                                  href={src}
                                  download={upload.fileName}
                                >
                                  Download attachment
                                </a>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                ))}
                {(reportFeed.data ?? []).length === 0 && (
                  <p className="rounded-lg border border-white/10 bg-[#09090B]/60 p-3 text-sm text-[#F8FAFC]/60">
                    No reports yet. Submit a report and it will appear here with full details.
                  </p>
                )}
              </div>
            </CardContent>
          </Card>
        </section>
      )}

      {activeSection === "edu" && (
        <section className="grid gap-4 lg:grid-cols-3">
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><BookOpen className="size-4" /> Edu Hub</CardTitle>
              <CardDescription>Awareness-first design for real-world impact</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="rounded-xl border border-[#EF4444]/30 bg-[#EF4444]/10 p-4">
                <h3 className="mb-1 font-semibold text-[#F8FAFC]">How Scams Work</h3>
                <p className="text-sm text-[#F8FAFC]/75">
                  Attackers exploit urgency, fear, rewards, and fake authority. They mimic trusted brands, ask for OTPs,
                  and push users to click malicious links quickly before verification.
                </p>
              </div>
              <div className="rounded-xl border border-[#10B981]/30 bg-[#10B981]/10 p-4">
                <h3 className="mb-1 font-semibold text-[#F8FAFC]">How To Stay Safe</h3>
                <p className="text-sm text-[#F8FAFC]/75">
                  Verify domain age, inspect sender domain, never share OTP/PIN, avoid unknown attachments, and report
                  suspicious campaigns. Pause first, then verify through official channels.
                </p>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Profile</CardTitle>
              <CardDescription>Identity and trust context</CardDescription>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-[#F8FAFC]/60">Name</p>
              <p className="mb-2 font-semibold">{userName}</p>
              <p className="text-xs text-[#F8FAFC]/60">Email</p>
              <p className="font-semibold">{userEmail}</p>
              <div className="mt-4 rounded-lg border border-[#7C3AED]/30 bg-[#7C3AED]/15 p-3 text-xs text-[#F8FAFC]/80">
                Impact-driven feature enabled: Edu Hub raises community readiness beyond raw detection metrics.
              </div>
            </CardContent>
          </Card>
        </section>
      )}

      {activeSection === "admin" && isAdmin && (
        <section className="grid gap-4 xl:grid-cols-3">
          <Card className="xl:col-span-2">
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><ShieldAlert className="size-4" /> Admin Tools: Review Reports</CardTitle>
              <CardDescription>Approve or reject reports with manual override reasoning</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <Input value={moderationReason} onChange={(e) => setModerationReason(e.target.value)} placeholder="Moderation reason for override" />
              <div className="space-y-2">
                {(adminReports.data ?? []).map((report) => (
                  <div key={report.id} className="rounded-xl border border-white/10 bg-[#09090B]/60 p-3">
                    <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                      <p className="font-semibold">{report.title}</p>
                      <span className={`rounded-full px-2 py-0.5 text-xs uppercase ${
                        report.status === "approved"
                          ? "bg-[#10B981]/20 text-[#10B981]"
                          : report.status === "rejected"
                            ? "bg-[#EF4444]/20 text-[#EF4444]"
                            : "bg-[#F59E0B]/20 text-[#F59E0B]"
                      }`}>
                        {report.status}
                      </span>
                    </div>
                    <p className="mb-2 text-xs text-[#F8FAFC]/50">
                      {new Date(report.createdAt).toLocaleString()} {report.user?.name ? `• by ${report.user.name}` : ""}
                    </p>
                    <p className="mb-2 text-sm text-[#F8FAFC]/80 whitespace-pre-wrap">{report.description}</p>
                    {report.url && <p className="mb-1 text-sm text-[#93C5FD] break-all">Link: {report.url}</p>}
                    {report.email && <p className="mb-2 text-sm text-[#FCD34D] break-all">Email: {report.email}</p>}

                    {report.uploads.length > 0 && (
                      <div className="mb-3 space-y-2 rounded-lg border border-white/10 bg-white/5 p-2">
                        <p className="text-xs uppercase tracking-wide text-[#10B981]">Attached Evidence</p>
                        {report.uploads.map((upload: { id: string; fileName: string; mimeType: string; sizeBytes: number; base64Data?: string | null }) => {
                          const safeBase64 = typeof upload.base64Data === "string" ? upload.base64Data : "";
                          const src = fileToDataUrl(upload.mimeType, safeBase64);
                          const isImage = upload.mimeType.startsWith("image/");

                          return (
                            <div key={upload.id} className="rounded-md border border-white/10 bg-[#09090B]/70 p-2">
                              <p className="text-xs text-[#F8FAFC]/70">
                                {upload.fileName} • {upload.mimeType} • {bytesToLabel(upload.sizeBytes)}
                              </p>
                              {isImage ? (
                                <Image
                                  src={src}
                                  alt={upload.fileName}
                                  width={1200}
                                  height={800}
                                  unoptimized
                                  className="mt-2 max-h-80 w-full rounded-md border border-white/10 object-contain"
                                />
                              ) : (
                                <a
                                  className="mt-2 inline-block text-xs text-[#93C5FD] underline"
                                  href={src}
                                  download={upload.fileName}
                                >
                                  Download attachment
                                </a>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    )}
                    <div className="flex gap-2">
                      <Button className="bg-[#10B981] text-[#09090B] hover:bg-[#10B981]/80" disabled={adminUpdate.isPending} onClick={() => adminUpdate.mutate({ reportId: report.id, status: "approved", reason: moderationReason })}>Approve</Button>
                      <Button className="bg-[#EF4444] text-[#F8FAFC] hover:bg-[#EF4444]/80" disabled={adminUpdate.isPending} onClick={() => adminUpdate.mutate({ reportId: report.id, status: "rejected", reason: moderationReason })}>Reject</Button>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2"><MessageSquare className="size-4" /> Chat Support</CardTitle>
              <CardDescription>Admin support assistant powered by Gemini</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="max-h-112 space-y-2 overflow-y-auto rounded-xl border border-white/10 bg-[#09090B]/60 p-3">
                {chatLog.map((entry, idx) => (
                  <div key={`${entry.role}-${idx}`} className={`rounded-lg p-2 text-sm ${entry.role === "assistant" ? "bg-[#7C3AED]/20 text-[#F8FAFC]" : "bg-white/10 text-[#F8FAFC]/90"}`}>
                    <p className="mb-1 text-xs uppercase opacity-70">{entry.role === "assistant" ? "Support Bot" : "Admin"}</p>
                    <p>{entry.text}</p>
                  </div>
                ))}
              </div>
              <Textarea value={chatInput} onChange={(e) => setChatInput(e.target.value)} placeholder="Ask support bot to draft user guidance" />
              <Button
                className="w-full bg-[#7C3AED] text-white hover:bg-[#7C3AED]/80"
                disabled={supportReply.isPending || chatInput.trim().length < 4}
                onClick={async () => {
                  const text = chatInput.trim();
                  setChatInput("");
                  setChatLog((prev) => [...prev, { role: "user", text }]);
                  const res = await supportReply.mutateAsync({ userMessage: text });
                  const replyText = typeof res.reply === "string"
                    ? res.reply
                    : "Support is currently busy. Please retry in a moment.";
                  setChatLog((prev) => [...prev, { role: "assistant", text: replyText }]);
                }}
              >
                <Bot className="mr-2 size-4" /> {supportReply.isPending ? "Thinking..." : "Send to Support Bot"}
              </Button>
            </CardContent>
          </Card>
        </section>
      )}
    </div>
  );
}

function MetricCard({ title, value, color }: { title: string; value: number; color: string }) {
  return (
    <Card>
      <CardHeader>
        <CardDescription>{title}</CardDescription>
      </CardHeader>
      <CardContent>
        <p className={`text-3xl font-bold ${color}`}>{value}</p>
      </CardContent>
    </Card>
  );
}

function ScanCard({
  icon,
  title,
  description,
  children,
}: {
  icon: ReactNode;
  title: string;
  description: string;
  children: ReactNode;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">{icon} {title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

function ResultPanel({ children }: { children: ReactNode }) {
  return <div className="rounded-lg border border-white/10 bg-[#09090B]/60 p-3">{children}</div>;
}
