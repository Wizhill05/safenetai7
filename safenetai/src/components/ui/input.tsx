import * as React from "react";

import { cn } from "~/lib/utils";

function Input({ className, type, ...props }: React.ComponentProps<"input">) {
  return (
    <input
      type={type}
      data-slot="input"
      className={cn(
        "flex h-10 w-full rounded-lg border border-white/15 bg-[#0F1117] px-3 py-2 text-sm text-[#F8FAFC] shadow-sm transition-colors placeholder:text-[#64748B] focus-visible:border-[#7C3AED] focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-60",
        className,
      )}
      {...props}
    />
  );
}

export { Input };
