import { Badge } from "~/components/ui/badge";
import { mapStatusLabel, type RiskStatus } from "~/lib/security";

const colorClasses: Record<RiskStatus, string> = {
  safe: "border-[#10B981]/40 bg-[#10B981]/20 text-[#6EE7B7]",
  suspicious: "border-[#F59E0B]/40 bg-[#F59E0B]/20 text-[#FCD34D]",
  dangerous: "border-[#EC4899]/40 bg-[#EC4899]/20 text-[#F472B6]",
};

export function StatusBadge({ status }: { status: RiskStatus }) {
  return <Badge className={colorClasses[status]}>{mapStatusLabel(status)}</Badge>;
}
