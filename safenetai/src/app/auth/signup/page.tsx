"use client";

import { signIn } from "next-auth/react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { Button } from "~/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "~/components/ui/card";
import { Input } from "~/components/ui/input";
import { api } from "~/trpc/react";

export default function SignupPage() {
  const router = useRouter();
  const register = api.auth.register.useMutation();

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  return (
    <main className="flex min-h-screen items-center justify-center bg-[#09090B] px-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Create SafeNet AI Account</CardTitle>
          <CardDescription>Secure your scans and reports with authentication</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="space-y-3"
            onSubmit={async (e) => {
              e.preventDefault();
              setError(null);

              try {
                await register.mutateAsync({
                  name: name || undefined,
                  email,
                  password,
                });

                const result = await signIn("credentials", {
                  email,
                  password,
                  redirect: false,
                  callbackUrl: "/dashboard",
                });

                if (result?.error) {
                  setError("Signup succeeded, but auto-login failed. Please sign in.");
                  router.push("/auth/login");
                  return;
                }

                router.push("/dashboard");
                router.refresh();
              } catch (mutationError) {
                const message =
                  mutationError instanceof Error
                    ? mutationError.message
                    : "Unable to create account.";
                setError(message);
              }
            }}
          >
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Name (optional)" />
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
              placeholder="Minimum 6 characters"
              minLength={6}
              required
            />
            {error && <p className="text-sm text-[#EC4899]">{error}</p>}
            <Button
              className="w-full bg-[#10B981] text-[#09090B] hover:bg-[#10B981]/80 shadow-lg shadow-emerald-500/20"
              disabled={register.isPending}
            >
              {register.isPending ? "Creating account..." : "Create account"}
            </Button>
            <p className="text-sm text-[#CBD5E1]">
              Already have an account? <Link href="/auth/login" className="text-[#7C3AED] hover:text-[#7C3AED]/80">Sign in</Link>
            </p>
          </form>
        </CardContent>
      </Card>
    </main>
  );
}
