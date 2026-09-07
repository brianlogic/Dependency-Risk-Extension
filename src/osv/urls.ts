import type { VulnSummary } from "../types";

export function advisoryUrl(vuln: Pick<VulnSummary, "id" | "aliases">): string {
  const ghsa =
    vuln.aliases.find((alias) => alias.startsWith("GHSA-")) ??
    (vuln.id.startsWith("GHSA-") ? vuln.id : undefined);
  if (ghsa) {
    return `https://github.com/advisories/${ghsa}`;
  }
  return `https://osv.dev/vulnerability/${vuln.id}`;
}

export function excerptDetails(details?: string, max = 720): string | undefined {
  if (!details?.trim()) {
    return undefined;
  }
  const text = details
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/!\[[^\]]*]\([^)]*\)/g, " ")
    .replace(/\[([^\]]+)]\([^)]*\)/g, "$1")
    .replace(/[#>*_`]/g, "")
    .replace(/\s+/g, " ")
    .trim();
  if (!text) {
    return undefined;
  }
  return text.length > max ? `${text.slice(0, max).trimEnd()}…` : text;
}

export function readingLinks(vuln: VulnSummary): { label: string; url: string }[] {
  const links: { label: string; url: string }[] = [];
  const seen = new Set<string>();
  const add = (label: string, url: string): void => {
    if (!/^https?:\/\//i.test(url) || seen.has(url)) {
      return;
    }
    seen.add(url);
    links.push({ label, url });
  };

  add(vuln.id.startsWith("GHSA-") ? "GitHub Advisory" : "OSV", advisoryUrl(vuln));
  for (const alias of vuln.aliases) {
    if (alias.startsWith("CVE-")) {
      add(alias, `https://osv.dev/vulnerability/${alias}`);
    }
  }
  for (const url of vuln.references) {
    add(linkLabel(url), url);
  }
  return links.slice(0, 8);
}

function linkLabel(url: string): string {
  try {
    const host = new URL(url).hostname.replace(/^www\./, "");
    if (host === "github.com" && url.includes("/advisories/")) {
      return "GitHub Advisory";
    }
    if (host === "nvd.nist.gov") {
      return "NVD";
    }
    if (host === "osv.dev") {
      return "OSV";
    }
    return host;
  } catch {
    return "Reference";
  }
}
