// Pure helpers for turning tool results into short human summaries, and for tokenising simple markdown.
export function summarize(tool, out) {
  if (!out) return "";
  if (out.error) return out.error;
  switch (tool) {
    case "find_affected_services":
      return `${out.total_services} service(s) exposed`;
    case "rank_services":
      return out.ranked?.length ? `top risk: ${out.ranked[0].service} (${out.ranked[0].priority})` : "no exposed services";
    case "explain_path":
      return out.exposed ? `${out.hops} hops via ${out.pulled_in_by ?? out.vulnerable_version}` : "not exposed";
    case "blast_radius":
      return `${out.total} upstream caller(s)`;
    case "get_owner":
      return `${out.team} (${out.oncall})`;
    case "recall_decisions":
      return out.precedents?.length ? `${out.precedents.length} precedent(s)` : "no precedent";
    case "save_decision":
      return out.supersedes ? `saved, supersedes ${out.supersedes}` : out.saved ? "saved" : "not saved";
    case "draft_ticket":
      return out.title;
    case "most_exposed_cves":
      return `${out.cves?.length ?? 0} CVE(s)`;
    case "find_cves_for_package":
      return `${out.cves?.length ?? 0} CVE(s) for ${out.package}`;
    case "get_cve":
      return `${out.id} (${out.severity})`;
    default:
      return "done";
  }
}

export function summarizeInput(input) {
  const vals = Object.values(input || {}).filter((v) => v !== undefined && v !== null && v !== "");
  const s = vals.map((v) => String(v)).join(", ");
  return s.length > 48 ? s.slice(0, 47) + "…" : s;
}

// Splits "a **bold** and `code`" into [{t:'text'|'bold'|'code', v}] without ever touching HTML.
export function tokenizeInline(text) {
  return String(text)
    .split(/(\*\*[^*]+\*\*|`[^`]+`)/g)
    .filter(Boolean)
    .map((p) =>
      p.startsWith("**") && p.endsWith("**") && p.length > 4
        ? { t: "bold", v: p.slice(2, -2) }
        : p.startsWith("`") && p.endsWith("`") && p.length > 2
          ? { t: "code", v: p.slice(1, -1) }
          : { t: "text", v: p },
    );
}

// Groups lines into blocks: paragraphs and bullet lists.
export function parseBlocks(text) {
  const blocks = [];
  for (const line of String(text).split("\n")) {
    if (/^\s*[-*] /.test(line)) {
      const item = line.replace(/^\s*[-*] /, "");
      const last = blocks[blocks.length - 1];
      if (last?.type === "list") last.items.push(item);
      else blocks.push({ type: "list", items: [item] });
    } else if (line.trim() === "") {
      blocks.push({ type: "gap" });
    } else {
      blocks.push({ type: "p", text: line });
    }
  }
  return blocks.filter((b, i) => !(b.type === "gap" && (i === 0 || blocks[i - 1].type === "gap")));
}

export function relativeTime(ms, now = Date.now()) {
  if (!ms) return "";
  const d = Math.max(0, now - ms);
  const day = 86_400_000;
  if (d < 3_600_000) return `${Math.max(1, Math.round(d / 60_000))}m ago`;
  if (d < day) return `${Math.round(d / 3_600_000)}h ago`;
  return `${Math.round(d / day)}d ago`;
}
