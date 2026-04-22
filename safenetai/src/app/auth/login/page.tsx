"use client";

import { signIn } from "next-auth/react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import { Button } from "~/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "~/components/ui/card";
import { Input } from "~/components/ui/input";

export default function LoginPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const callbackUrl = searchParams.get("callbackUrl") ?? "/dashboard";

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  return (
    <main className="flex min-h-screen items-center justify-center bg-[#09090B] px-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Sign in to SafeNet AI</CardTitle>
          <CardDescription>Access your protected dashboard and scan history</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="space-y-3"
            onSubmit={async (e) => {
              e.preventDefault();
              setIsLoading(true);
              setError(null);

              const result = await signIn("credentials", {
                email,
                password,
                redirect: false,
                callbackUrl,
              });

              setIsLoading(false);

              if (result?.error) {
                setError("Invalid email or password.");
                return;
              }

              router.push(callbackUrl);
              router.refresh();
            }}
          >
            <Input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              required
            />
            <Input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password"
              required
            />
            {error && <p className="text-sm text-[#EC4899]">{error}</p>}
            <Button className="w-full bg-[#7C3AED] text-white hover:bg-[#7C3AED]/80 shadow-lg shadow-purple-500/20" disabled={isLoading}>
              {isLoading ? "Signing in..." : "Sign in"}
            </Button>
            <p className="text-sm text-[#CBD5E1]">
              New user? <Link href="/auth/signup" className="text-[#10B981] hover:text-[#10B981]/80">Create an account</Link>
            </p>
          </form>
        </CardContent>
      </Card>
    </main>
  );
}
