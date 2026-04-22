import * as React from "react";

import { cn } from "~/lib/utils";

function Textarea({ className, ...props }: React.ComponentProps<"textarea">) {
  return (
    <textarea
      data-slot="textarea"
      className={cn(
        "flex min-h-28 w-full rounded-lg border border-white/15 bg-white/5 px-3 py-2 text-sm text-[#E5E7EB] shadow-sm transition-colors placeholder:text-[#9CA3AF] focus-visible:border-[#2563EB] focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-60",
        className,
      )}
      {...props}
    />
  );
}

export { Textarea };
