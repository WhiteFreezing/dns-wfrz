"use client";

import { useMemo, useState } from "react";

// Cloudflare DNS-over-HTTPS — JSON API, CORS-enabled, free, no auth.
const DOH = "https://cloudflare-dns.com/dns-query";

// IANA → registry RDAP bootstrap. rdap.org redirects to the authoritative
// registry server (e.g. Verisign for .com). Final response is CORS *.
const RDAP = "https://rdap.org/domain";

// RIPEstat: network-info (IP→ASN), as-overview (ASN→holder), maxmind-geo-lite.
const RIPE = "https://stat.ripe.net/data";

// crt.sh: Certificate Transparency search → cheap passive subdomain enumeration.
const CRTSH = "https://crt.sh";

const RECORD_TYPES = [
  { id: "A",     num: 1 },
  { id: "AAAA",  num: 28 },
  { id: "CNAME", num: 5 },
  { id: "MX",    num: 15 },
  { id: "TXT",   num: 16 },
  { id: "NS",    num: 2 },
  { id: "SOA",   num: 6 },
  { id: "CAA",   num: 257 },
  { id: "SRV",   num: 33 },
  { id: "DNSKEY",num: 48 },
] as const;

type RecordType = (typeof RECORD_TYPES)[number]["id"];

type Answer = { name: string; type: number; TTL: number; data: string };
type DohResult = { Status: number; Answer?: Answer[]; AD?: boolean };

type IpInfo = {
  ip: string;
  asn?: string;
  holder?: string;
  prefix?: string;
  country?: string;
  city?: string;
  lat?: number;
  lon?: number;
};

type Rdap = {
  ldhName?: string;
  status?: string[];
  nameservers?: { ldhName: string }[];
  events?: { eventAction: string; eventDate: string }[];
  entities?: { roles?: string[]; vcardArray?: any }[];
};

type Result = {
  domain: string;
  records: Partial<Record<RecordType, Answer[]>>;
  status: Partial<Record<RecordType, number>>;
  dnssec: boolean;
  ips: Record<string, IpInfo>;
  mxTargets: Record<string, string[]>; // mx hostname → A records
  subdomains: string[];
  rdap?: Rdap;
  email: {
    spf?: string;
    dmarc?: string;
    dkimSelectors: string[];
    mxAdvertised: number;
  };
};

export default function HomePage() {
  const [domain, setDomain] = useState("github.com");
  const [result, setResult] = useState<Result | null>(null);
  const [loading, setLoading] = useState<string>("");
  const [section, setSection] = useState<"topology" | "records" | "subs" | "ips" | "whois">("topology");

  async function probe() {
    const d = domain.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0];
    if (!d) return;
    setResult(null);
    setLoading("Resolving DNS records…");

    // 1) Parallel DoH for all record types + DNSSEC.
    // do=true asks for DNSSEC; the response then also includes RRSIG (type 46)
    // records covering the answer. We keep the AD flag (chain valid?) but
    // drop the signatures themselves from the per-type buckets.
    const dohJobs = RECORD_TYPES.map(async (rt) => {
      const r = await fetch(`${DOH}?name=${encodeURIComponent(d)}&type=${rt.num}&do=true`, {
        headers: { Accept: "application/dns-json" },
      });
      const j: DohResult = await r.json();
      return { id: rt.id, num: rt.num, j };
    });
    const dohRes = await Promise.all(dohJobs);

    const records: Partial<Record<RecordType, Answer[]>> = {};
    const status: Partial<Record<RecordType, number>> = {};
    let dnssec = false;
    for (const { id, num, j } of dohRes) {
      records[id] = (j.Answer ?? []).filter((a) => a.type === num);
      status[id] = j.Status;
      if (j.AD) dnssec = true;
    }

    // 2) DMARC at _dmarc.<domain>
    setLoading("Resolving DMARC…");
    try {
      const r = await fetch(`${DOH}?name=${encodeURIComponent("_dmarc." + d)}&type=16`, { headers: { Accept: "application/dns-json" } });
      const j: DohResult = await r.json();
      const dmarcRec = (j.Answer ?? []).filter((a) => a.type === 16).find((a) => unq(a.data).startsWith("v=DMARC1"));
      if (dmarcRec) (records.TXT ||= []).push({ ...dmarcRec, data: dmarcRec.data });
    } catch {}

    // Resolve A records for each MX target (so the topology graph can connect MX→IP→ASN).
    setLoading("Resolving MX targets…");
    const mxTargets: Record<string, string[]> = {};
    for (const mx of records.MX ?? []) {
      const host = mx.data.split(/\s+/).slice(1).join(" ").replace(/\.$/, "");
      try {
        const r = await fetch(`${DOH}?name=${encodeURIComponent(host)}&type=1`, { headers: { Accept: "application/dns-json" } });
        const j: DohResult = await r.json();
        mxTargets[host] = (j.Answer ?? []).filter((a) => a.type === 1).map((a) => a.data);
      } catch {}
    }

    // Aggregate every IP we've seen across A/AAAA + MX.
    const ipSet = new Set<string>();
    (records.A ?? []).forEach((a) => ipSet.add(a.data));
    (records.AAAA ?? []).forEach((a) => ipSet.add(a.data));
    Object.values(mxTargets).flat().forEach((ip) => ipSet.add(ip));
    const ips: Record<string, IpInfo> = {};

    // 3) Per-IP ASN + geo via RIPEstat.
    setLoading(`Resolving ASN + geo for ${ipSet.size} IP(s)…`);
    await Promise.all([...ipSet].map(async (ip) => {
      const info: IpInfo = { ip };
      try {
        const [ni, geo] = await Promise.all([
          fetch(`${RIPE}/network-info/data.json?resource=${encodeURIComponent(ip)}`).then((r) => r.json()),
          fetch(`${RIPE}/maxmind-geo-lite/data.json?resource=${encodeURIComponent(ip)}`).then((r) => r.json()),
        ]);
        const asn = ni?.data?.asns?.[0];
        info.asn = asn ? "AS" + asn : undefined;
        info.prefix = ni?.data?.prefix;
        const loc = geo?.data?.located_resources?.[0]?.locations?.[0];
        if (loc) { info.country = loc.country; info.city = loc.city; info.lat = loc.latitude; info.lon = loc.longitude; }
        if (asn) {
          const ov = await fetch(`${RIPE}/as-overview/data.json?resource=AS${asn}`).then((r) => r.json());
          info.holder = ov?.data?.holder;
        }
      } catch {}
      ips[ip] = info;
    }));

    // 4) Subdomain enumeration via crt.sh (Certificate Transparency).
    setLoading("Mining Certificate Transparency for subdomains…");
    let subdomains: string[] = [];
    try {
      const r = await fetch(`${CRTSH}/?q=${encodeURIComponent("%." + d)}&output=json&exclude=expired`);
      if (r.ok) {
        const j = await r.json();
        const set = new Set<string>();
        for (const c of j as { name_value: string }[]) {
          for (const n of c.name_value.split("\n")) {
            const name = n.trim().toLowerCase();
            if (name.endsWith("." + d) && !name.startsWith("*")) set.add(name);
          }
        }
        subdomains = [...set].sort();
      }
    } catch {}

    // 5) RDAP — domain registration data.
    setLoading("Fetching RDAP / registrar…");
    let rdap: Rdap | undefined;
    try {
      const r = await fetch(`${RDAP}/${encodeURIComponent(d)}`, { redirect: "follow" });
      if (r.ok) rdap = await r.json();
    } catch {}

    // Parse email-security TXT records.
    const txt = (records.TXT ?? []).map((a) => unq(a.data));
    const spf = txt.find((t) => t.startsWith("v=spf1"));
    const dmarc = txt.find((t) => t.startsWith("v=DMARC1"));
    const dkimSelectors: string[] = []; // can't enumerate without selector list

    setResult({
      domain: d,
      records, status, dnssec, ips, mxTargets, subdomains, rdap,
      email: { spf, dmarc, dkimSelectors, mxAdvertised: (records.MX ?? []).length },
    });
    setLoading("");
  }

  return (
    <main className="min-h-screen">
      {/* ── TOPBAR ────────────────────────────────────────────── */}
      <nav className="border-b border-border/60 sticky top-0 z-20 bg-ink/85 backdrop-blur">
        <div className="max-w-7xl mx-auto px-5 h-12 flex items-center gap-5">
          <a href="/" className="font-mono font-bold text-sm tracking-tight">
            <span className="text-brand">dns</span>
            <span className="text-dim">.wfrz.eu</span>
          </a>
          <span className="text-xs text-dim hidden md:inline">DNS &amp; infra inspector</span>
          <div className="ml-auto flex items-center gap-4 text-xs text-dim">
            <a href="https://wfrz.eu" className="hover:text-text">wfrz.eu</a>
            <a href="https://github.com/WhiteFreezing/dns-wfrz" target="_blank" rel="noopener" className="hover:text-text">github</a>
          </div>
        </div>
      </nav>

      <section className="max-w-7xl mx-auto px-5 pt-10 pb-24">

        {/* ── SEARCH ──────────────────────────────────────────── */}
        <div className="max-w-2xl">
          <div className="text-xs uppercase tracking-[0.16em] text-dim mb-2">probe a domain</div>
          <div className="surface flex items-center px-3.5 focus-within:border-brand transition">
            <span className="text-dim font-mono text-sm select-none mr-2">$</span>
            <input
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && probe()}
              className="bg-transparent flex-1 outline-none font-mono text-base placeholder:text-dim/60 py-3"
              placeholder="example.com"
              spellCheck={false}
              autoFocus
            />
            <button onClick={probe} disabled={!!loading} className="btn">
              {loading ? "…" : "Probe"}
            </button>
          </div>

          {!result && !loading && (
            <div className="flex items-center gap-2 mt-3 text-xs text-dim flex-wrap">
              <span>examples:</span>
              {["github.com", "cloudflare.com", "anthropic.com", "wfrz.eu"].map((d) => (
                <button key={d} onClick={() => { setDomain(d); setTimeout(probe, 0); }}
                  className="font-mono text-dim hover:text-brand transition underline-offset-4 hover:underline decoration-dotted">{d}</button>
              ))}
            </div>
          )}
        </div>

        {loading && (
          <div className="mt-6 font-mono text-sm text-dim flex items-center gap-3">
            <span className="w-1.5 h-1.5 bg-brand rounded-full" />
            <span>{loading}</span>
          </div>
        )}

        {result && (
          <div className="mt-10 space-y-8">
            <SummaryBar r={result} />

            {/* tabs — underline style */}
            <div className="border-b border-border/60 -mb-px overflow-x-auto">
              <div className="flex gap-1 min-w-fit">
                <SectionTab on={section === "topology"} onClick={() => setSection("topology")}>topology</SectionTab>
                <SectionTab on={section === "records"}  onClick={() => setSection("records")}>records</SectionTab>
                <SectionTab on={section === "ips"}      onClick={() => setSection("ips")}>
                  ips <span className="ml-1 text-dim">({Object.keys(result.ips).length})</span>
                </SectionTab>
                <SectionTab on={section === "subs"}     onClick={() => setSection("subs")}>
                  subdomains <span className="ml-1 text-dim">({result.subdomains.length})</span>
                </SectionTab>
                <SectionTab on={section === "whois"}    onClick={() => setSection("whois")}>whois</SectionTab>
              </div>
            </div>

            {section === "topology" && <Topology r={result} />}
            {section === "records"  && <RecordsView r={result} />}
            {section === "ips"      && <IpsView r={result} />}
            {section === "subs"     && <SubsView r={result} />}
            {section === "whois"    && <WhoisView r={result} />}
          </div>
        )}
      </section>

      <footer className="border-t border-border/60 py-6 text-xs text-dim">
        <div className="max-w-7xl mx-auto px-5 flex items-center justify-between flex-wrap gap-3 font-mono">
          <div>data: cloudflare-doh · ripestat · crt.sh · rdap</div>
          <div>browser-side, no backend</div>
        </div>
      </footer>
    </main>
  );
}

// ISO-3166 alpha-2 → keep as small mono text instead of emoji flag.
function cc(country?: string): string {
  return (country && country.length === 2) ? country.toUpperCase() : "";
}

function unq(s: string) { return s.startsWith('"') && s.endsWith('"') ? s.slice(1, -1).replace(/"\s+"/g, "") : s; }

function SectionTab({ on, onClick, children }: { on: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button onClick={onClick}
      className={`px-3.5 py-2.5 text-sm font-mono whitespace-nowrap border-b-2 transition -mb-px ${
        on ? "border-brand text-text" : "border-transparent text-dim hover:text-text"
      }`}>
      {children}
    </button>
  );
}

// ── SUMMARY ──────────────────────────────────────────────────────

function SummaryBar({ r }: { r: Result }) {
  const reg = r.rdap?.events?.find((e) => e.eventAction === "registration")?.eventDate;
  const ageYears = reg ? ((Date.now() - new Date(reg).getTime()) / 31557600000) : null;
  const ipCount = Object.keys(r.ips).length;
  const nsCount = r.records.NS?.length ?? 0;
  const mxCount = r.records.MX?.length ?? 0;
  const countries = [...new Set(Object.values(r.ips).map((i) => i.country).filter(Boolean) as string[])];
  const registrar = getRegistrar(r.rdap);

  return (
    <div>
      <div className="flex items-baseline gap-4 flex-wrap">
        <h1 className="font-mono font-bold text-3xl md:text-4xl tracking-tight">
          {r.domain}
        </h1>
        <span className={`text-xs font-mono uppercase tracking-wider ${r.dnssec ? "text-brand" : "text-amber-300/80"}`}>
          DNSSEC {r.dnssec ? "signed" : "off"}
        </span>
      </div>
      {registrar && (
        <div className="text-sm text-dim mt-1">
          registered with <span className="text-text">{registrar}</span>
          {ageYears !== null && <> · <span className="num">{ageYears.toFixed(1)}</span> years ago</>}
        </div>
      )}

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-px bg-border/50 border border-border/50 rounded-lg overflow-hidden mt-5">
        <Stat label="nameservers" value={nsCount} warn={nsCount < 2} />
        <Stat label="ip hosts"    value={ipCount} />
        <Stat label="mx records"  value={mxCount} warn={mxCount === 0} />
        <Stat label="countries"   value={countries.length} hint={countries.join(" ")} />
      </div>
    </div>
  );
}

function Stat({ label, value, warn, hint }: { label: string; value: number; warn?: boolean; hint?: string }) {
  return (
    <div className="bg-surface px-4 py-3">
      <div className="text-[10px] uppercase tracking-wider text-dim font-mono">{label}</div>
      <div className="flex items-baseline gap-2 mt-1">
        <span className={`num text-2xl font-bold ${warn ? "text-amber-300" : "text-text"}`}>{value}</span>
        {hint && <span className="text-xs text-dim font-mono truncate">{hint}</span>}
      </div>
    </div>
  );
}

function getRegistrar(rdap?: Rdap): string | undefined {
  const ent = rdap?.entities?.find((e) => e.roles?.includes("registrar"));
  const fn = ent?.vcardArray?.[1]?.find?.((v: any[]) => v[0] === "fn");
  return fn?.[3];
}

// ── TOPOLOGY ─────────────────────────────────────────────────────
// Tree layout: nameservers on top, domain in middle, MX (left) + A/AAAA
// (right) flanking it, CNAME chain below. HTML cards for content,
// SVG underlay for bezier connectors. No overlap, no truncation drama.

type TopoNode = {
  id: string;
  kind: "ns" | "web" | "mx" | "cname";
  x: number; y: number; w: number; h: number;
  title: string;       // primary label (hostname / IP)
  sub?: string;        // secondary line (ASN holder, country, priority…)
  badge?: string;      // small chip (e.g. AAAA, 10)
  ip?: string;
};

function Topology({ r }: { r: Result }) {
  const W = 1200, H = 840;

  // domain at exact center
  const domain = { x: W / 2 - 130, y: H / 2 - 38, w: 260, h: 76 };
  const domainCx = domain.x + domain.w / 2;
  const domainCy = domain.y + domain.h / 2;

  // ── 1) Nameservers — top row, wrap into rows of max 4 ──────────
  const ns = (r.records.NS ?? []).map((a, i) => ({ id: "ns:" + i, host: a.data.replace(/\.$/, "") }));
  const NS_W = 230, NS_H = 40, NS_GAP = 16, NS_PER_ROW = Math.min(4, Math.max(1, ns.length));
  const nsRows = Math.ceil(ns.length / NS_PER_ROW);
  const nsTotalW = NS_PER_ROW * NS_W + (NS_PER_ROW - 1) * NS_GAP;
  const nsStartX = (W - nsTotalW) / 2;
  const nsStartY = 30;
  const nsNodes: TopoNode[] = ns.map((n, i) => {
    const row = Math.floor(i / NS_PER_ROW);
    const col = i % NS_PER_ROW;
    // last row may be shorter — centre it
    const rowItems = (row === nsRows - 1) ? (ns.length - row * NS_PER_ROW) : NS_PER_ROW;
    const rowW = rowItems * NS_W + (rowItems - 1) * NS_GAP;
    const rowStart = (W - rowW) / 2;
    return {
      id: n.id, kind: "ns",
      x: rowStart + col * (NS_W + NS_GAP),
      y: nsStartY + row * (NS_H + 10),
      w: NS_W, h: NS_H,
      title: n.host,
    };
  });

  // ── 2) Web (A + AAAA) — right column ───────────────────────────
  const a4 = (r.records.A ?? []).map((rec) => ({ ip: rec.data, kind: "A" as const }));
  const a6 = (r.records.AAAA ?? []).map((rec) => ({ ip: rec.data, kind: "AAAA" as const }));
  const web = [...a4, ...a6];
  const WEB_W = 260, WEB_H = 76, WEB_GAP = 14;
  const webX = W - WEB_W - 30;
  const webStartY = domainCy - ((web.length * WEB_H + (web.length - 1) * WEB_GAP) / 2);
  const webNodes: TopoNode[] = web.map((w0, i) => {
    const info = r.ips[w0.ip];
    return {
      id: "web:" + w0.kind + i, kind: "web",
      x: webX, y: webStartY + i * (WEB_H + WEB_GAP), w: WEB_W, h: WEB_H,
      title: w0.ip,
      sub: info?.holder
        ? `${info.asn ?? ""} · ${info.holder}${info.country ? " · " + info.country : ""}`
        : "—",
      badge: w0.kind,
      ip: w0.ip,
    };
  });

  // ── 3) Mail (MX) — left column ─────────────────────────────────
  const mx = (r.records.MX ?? []).map((rec) => {
    const parts = rec.data.split(/\s+/);
    return { prio: parts[0], host: parts.slice(1).join(" ").replace(/\.$/, "") };
  });
  const MX_W = 260, MX_H = 76, MX_GAP = 14;
  const mxStartY = domainCy - ((mx.length * MX_H + (mx.length - 1) * MX_GAP) / 2);
  const mxNodes: TopoNode[] = mx.map((m, i) => {
    const ipForHost = (r.mxTargets[m.host] || [])[0];
    const info = ipForHost ? r.ips[ipForHost] : undefined;
    return {
      id: "mx:" + i, kind: "mx",
      x: 30, y: mxStartY + i * (MX_H + MX_GAP), w: MX_W, h: MX_H,
      title: m.host,
      sub: info?.holder
        ? `${info.asn ?? ""} · ${info.holder}${info.country ? " · " + info.country : ""}`
        : ipForHost ?? "—",
      badge: m.prio,
      ip: ipForHost,
    };
  });

  // ── 4) CNAME — bottom row ──────────────────────────────────────
  const cn = (r.records.CNAME ?? []).map((a) => a.data.replace(/\.$/, ""));
  const CN_W = 230, CN_H = 40, CN_GAP = 16;
  const cnTotalW = cn.length * CN_W + (cn.length - 1) * CN_GAP;
  const cnStartX = (W - cnTotalW) / 2;
  const cnY = H - CN_H - 30;
  const cnNodes: TopoNode[] = cn.map((host, i) => ({
    id: "cn:" + i, kind: "cname",
    x: cnStartX + i * (CN_W + CN_GAP), y: cnY, w: CN_W, h: CN_H,
    title: host,
  }));

  const allNodes = [...nsNodes, ...webNodes, ...mxNodes, ...cnNodes];

  // Connectors: from edge-of-domain → edge-of-card, bezier curve
  function connectorPath(n: TopoNode): string {
    const cx = n.x + n.w / 2;
    const cy = n.y + n.h / 2;
    // anchor points on each card
    const ax = n.kind === "ns"    ? cx
            : n.kind === "cname"  ? cx
            : n.kind === "mx"     ? n.x + n.w
            :                       n.x;
    const ay = n.kind === "ns"    ? n.y + n.h
            : n.kind === "cname"  ? n.y
            :                       cy;
    // anchor points on domain
    const dx = n.kind === "mx"    ? domain.x
            : n.kind === "web"    ? domain.x + domain.w
            :                       domainCx;
    const dy = n.kind === "ns"    ? domain.y
            : n.kind === "cname"  ? domain.y + domain.h
            :                       domainCy;
    // control points pull the curve nicely
    const cp1x = n.kind === "ns" || n.kind === "cname" ? dx : (dx + ax) / 2;
    const cp1y = n.kind === "ns" || n.kind === "cname" ? (dy + ay) / 2 : dy;
    const cp2x = n.kind === "ns" || n.kind === "cname" ? ax : (dx + ax) / 2;
    const cp2y = n.kind === "ns" || n.kind === "cname" ? (dy + ay) / 2 : ay;
    return `M ${dx} ${dy} C ${cp1x} ${cp1y}, ${cp2x} ${cp2y}, ${ax} ${ay}`;
  }

  const COLORS: Record<TopoNode["kind"], string> = {
    ns: "#22d3ee", web: "#34d399", mx: "#a78bfa", cname: "#fbbf24",
  };
  const LABELS: Record<TopoNode["kind"], string> = {
    ns: "Nameservers", web: "Web (A / AAAA)", mx: "Mail (MX)", cname: "CNAME",
  };

  const groupsPresent = (Object.keys(LABELS) as TopoNode["kind"][])
    .filter((k) => allNodes.some((n) => n.kind === k));

  return (
    <div>
      <div className="flex items-baseline justify-between mb-3 flex-wrap gap-3">
        <div className="text-xs uppercase tracking-[0.16em] text-dim">topology</div>
        <div className="flex gap-3 text-[11px] font-mono">
          {groupsPresent.map((k) => (
            <span key={k} className="flex items-center gap-1.5 text-dim">
              <span className="w-2 h-2 rounded-full" style={{ background: COLORS[k] }} />
              {LABELS[k].toLowerCase()}
            </span>
          ))}
        </div>
      </div>

      <div className="surface overflow-x-auto">
        <div className="relative" style={{ width: W, height: H, minWidth: 900 }}>
          <svg className="absolute inset-0 pointer-events-none" viewBox={`0 0 ${W} ${H}`}
               width={W} height={H}>
            {allNodes.map((n) => (
              <path key={"p:" + n.id} d={connectorPath(n)} fill="none"
                stroke={COLORS[n.kind]} strokeOpacity="0.5" strokeWidth="1" />
            ))}
          </svg>

          {nsNodes.length > 0 && (
            <SectionLabel x={W / 2}              y={6}                color={COLORS.ns}    text="nameservers" count={nsNodes.length} />
          )}
          {webNodes.length > 0 && (
            <SectionLabel x={webX + WEB_W / 2}   y={webStartY - 22}   color={COLORS.web}   text="web"         count={webNodes.length} />
          )}
          {mxNodes.length > 0 && (
            <SectionLabel x={30 + MX_W / 2}      y={mxStartY - 22}    color={COLORS.mx}    text="mail"        count={mxNodes.length} />
          )}
          {cnNodes.length > 0 && (
            <SectionLabel x={W / 2}              y={cnY - 22}         color={COLORS.cname} text="cname"       count={cnNodes.length} />
          )}

          {/* domain — clean rectangle, no glow */}
          <div className="absolute rounded-md border border-brand/70 bg-ink flex flex-col items-center justify-center"
            style={{ left: domain.x, top: domain.y, width: domain.w, height: domain.h }}>
            <div className="text-[10px] uppercase tracking-[0.2em] text-dim font-mono">domain</div>
            <div className="text-text text-lg font-extrabold font-mono mt-1 truncate px-3 max-w-full">{r.domain}</div>
          </div>

          {allNodes.map((n) => (
            <NodeCard
              key={n.id} n={n} color={COLORS[n.kind]}
              countryCode={n.ip ? r.ips[n.ip]?.country : undefined}
            />
          ))}
        </div>
      </div>

      {allNodes.length === 0 && (
        <div className="text-sm text-dim text-center py-8">no records to graph for <code className="text-brand">{r.domain}</code></div>
      )}
    </div>
  );
}

function SectionLabel({ x, y, color, text, count }: { x: number; y: number; color: string; text: string; count: number }) {
  return (
    <div className="absolute -translate-x-1/2 flex items-center gap-2 font-mono text-[10px]" style={{ left: x, top: y }}>
      <span className="uppercase tracking-[0.18em] text-dim">{text}</span>
      <span style={{ color }}>{count}</span>
    </div>
  );
}

function NodeCard({ n, color, countryCode }: { n: TopoNode; color: string; countryCode?: string }) {
  const isPill = n.kind === "ns" || n.kind === "cname";
  return (
    <div className="absolute rounded-md border border-border/60 bg-surface transition hover:border-text hover:z-10"
      style={{ left: n.x, top: n.y, width: n.w, height: n.h }}
      title={n.ip ? `${n.title} → ${n.ip}` : n.title}>
      {isPill ? (
        <div className="px-3 h-full flex items-center gap-2">
          <span className="w-1 h-1 rounded-full shrink-0" style={{ background: color }} />
          <span className="font-mono text-xs text-text truncate">{n.title}</span>
        </div>
      ) : (
        <div className="px-3 py-2 h-full flex flex-col justify-between">
          <div className="flex items-baseline gap-2">
            {n.badge && (
              <span className="text-[10px] font-mono shrink-0" style={{ color }}>{n.badge}</span>
            )}
            <span className="font-mono text-[13px] font-semibold text-text leading-tight break-all line-clamp-2">{n.title}</span>
            {countryCode && (
              <span className="ml-auto text-[10px] font-mono text-dim shrink-0">{cc(countryCode)}</span>
            )}
          </div>
          {n.sub && (
            <div className="text-[11px] text-dim font-mono truncate mt-1">{n.sub}</div>
          )}
        </div>
      )}
    </div>
  );
}

// ── RECORDS VIEW ─────────────────────────────────────────────────

function RecordsView({ r }: { r: Result }) {
  const present = RECORD_TYPES.filter((rt) => (r.records[rt.id]?.length ?? 0) > 0);
  const empty = RECORD_TYPES.filter((rt) => !(r.records[rt.id]?.length));

  return (
    <div className="surface divide-y divide-border/50">
      {present.map((rt) => {
        const ans = r.records[rt.id] ?? [];
        return (
          <div key={rt.id} className="grid grid-cols-[80px_1fr] hover:bg-muted/20 transition">
            <div className="px-4 py-3 border-r border-border/40 flex items-center">
              <code className="text-text font-mono font-bold text-sm">{rt.id}</code>
            </div>
            <div className="divide-y divide-border/30">
              {ans.map((a, i) => (
                <div key={i} className="px-4 py-2.5 flex items-start justify-between gap-4">
                  <code className="text-sm font-mono break-all leading-relaxed text-text/90 flex-1">{a.data}</code>
                  <span className="text-[10px] font-mono text-dim whitespace-nowrap shrink-0 mt-0.5">{a.TTL}s</span>
                </div>
              ))}
            </div>
          </div>
        );
      })}

      {empty.length > 0 && (
        <div className="px-4 py-3 flex items-center gap-3 text-xs">
          <span className="text-dim uppercase tracking-wider">absent</span>
          <span className="font-mono text-dim/70">{empty.map((rt) => rt.id).join("  ")}</span>
        </div>
      )}
    </div>
  );
}

// ── IPs VIEW ─────────────────────────────────────────────────────

function IpsView({ r }: { r: Result }) {
  const ips = Object.values(r.ips);
  if (!ips.length) return <div className="text-sm text-dim">No IPs to analyze.</div>;

  const byHolder = new Map<string, IpInfo[]>();
  ips.forEach((ip) => {
    const key = ip.holder ?? "Unknown";
    if (!byHolder.has(key)) byHolder.set(key, []);
    byHolder.get(key)!.push(ip);
  });

  return (
    <div className="space-y-6">
      {[...byHolder.entries()].map(([holder, group]) => {
        const first = group[0];
        return (
          <div key={holder} className="surface overflow-hidden">
            <div className="px-4 py-3 border-b border-border/50 flex items-baseline justify-between flex-wrap gap-2">
              <div className="flex items-baseline gap-3">
                <span className="text-sm font-semibold">{holder}</span>
                <span className="text-xs text-dim font-mono">
                  {first?.asn} {first?.country ? "· " + first.country : ""} {first?.city ? "· " + first.city : ""}
                </span>
              </div>
              <span className="text-[11px] text-dim font-mono">{group.length} {group.length === 1 ? "ip" : "ips"}</span>
            </div>
            <div className="divide-y divide-border/30">
              {group.map((ip) => (
                <div key={ip.ip} className="px-4 py-2.5 flex items-center justify-between gap-4 flex-wrap">
                  <div className="flex items-baseline gap-3 min-w-0">
                    <code className="font-mono text-text font-semibold break-all">{ip.ip}</code>
                    {ip.prefix && <code className="text-[11px] text-dim font-mono">{ip.prefix}</code>}
                  </div>
                  <div className="flex gap-3 text-[11px] font-mono">
                    {ip.lat !== undefined && (
                      <a className="text-dim hover:text-text" target="_blank" rel="noopener"
                        href={`https://www.openstreetmap.org/?mlat=${ip.lat}&mlon=${ip.lon}&zoom=8`}>map</a>
                    )}
                    <a className="text-dim hover:text-text" target="_blank" rel="noopener" href={`https://bgp.he.net/ip/${ip.ip}`}>he.net</a>
                    <a className="text-dim hover:text-text" target="_blank" rel="noopener" href={`https://stat.ripe.net/${ip.ip}`}>ripe</a>
                    <a className="text-dim hover:text-text" target="_blank" rel="noopener" href={`https://www.shodan.io/host/${ip.ip}`}>shodan</a>
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── SUBDOMAINS VIEW ──────────────────────────────────────────────

function SubsView({ r }: { r: Result }) {
  const [filter, setFilter] = useState("");
  const subs = useMemo(() => {
    if (!filter) return r.subdomains;
    return r.subdomains.filter((s) => s.includes(filter));
  }, [filter, r.subdomains]);

  if (!r.subdomains.length) return (
    <div className="text-sm text-dim">
      No subdomains found in Certificate Transparency logs.
    </div>
  );

  return (
    <div>
      <div className="flex items-baseline justify-between gap-4 flex-wrap mb-4">
        <div className="flex items-baseline gap-3">
          <span className="num text-2xl font-bold text-text">{r.subdomains.length}</span>
          <span className="text-xs text-dim">subdomains in CT logs</span>
        </div>
        <div className="flex gap-2 items-center">
          <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="filter…"
            className="surface px-3 py-1.5 font-mono text-sm bg-surface outline-none focus:border-brand transition w-44" />
          <a className="font-mono text-xs text-dim hover:text-text" target="_blank" rel="noopener" href={`https://crt.sh/?q=%25.${r.domain}`}>raw crt.sh →</a>
        </div>
      </div>

      {filter && subs.length !== r.subdomains.length && (
        <div className="text-xs text-dim mb-2 font-mono">{subs.length} / {r.subdomains.length}</div>
      )}

      <div className="surface divide-y divide-border/30">
        {subs.map((s) => {
          const prefix = s.replace("." + r.domain, "");
          return (
            <a key={s} target="_blank" rel="noopener" href={`https://${s}`}
              className="group px-4 py-2 flex items-baseline gap-2 hover:bg-muted/30 transition font-mono text-xs">
              <span className="text-text">{prefix}</span>
              <span className="text-dim/70">.{r.domain}</span>
              <span className="ml-auto text-dim opacity-0 group-hover:opacity-100">→</span>
            </a>
          );
        })}
      </div>
    </div>
  );
}

// ── WHOIS + EMAIL VIEW ───────────────────────────────────────────

function WhoisView({ r }: { r: Result }) {
  const reg = r.rdap?.events?.find((e) => e.eventAction === "registration");
  const exp = r.rdap?.events?.find((e) => e.eventAction === "expiration");
  const upd = r.rdap?.events?.find((e) => e.eventAction === "last changed");
  const registrar = getRegistrar(r.rdap);
  const daysToExpiry = exp ? Math.round((new Date(exp.eventDate).getTime() - Date.now()) / 86400000) : null;

  return (
    <div className="grid md:grid-cols-2 gap-6">
      <div>
        <div className="text-xs uppercase tracking-[0.16em] text-dim mb-3">registration</div>
        {r.rdap ? (
          <div className="surface divide-y divide-border/40">
            <KV k="registrar" v={registrar ?? "—"} />
            <KV k="registered" v={reg?.eventDate?.slice(0, 10) ?? "—"} />
            <KV k="updated"    v={upd?.eventDate?.slice(0, 10) ?? "—"} />
            <KV k="expires"    v={exp?.eventDate?.slice(0, 10) ?? "—"}
              hint={daysToExpiry !== null ? `${daysToExpiry}d` : undefined}
              accent={exp ? expiryAccent(exp.eventDate) : undefined} />
            {r.rdap.status && r.rdap.status.length > 0 && (
              <div className="px-4 py-2.5">
                <div className="text-[11px] uppercase tracking-wider text-dim font-mono mb-1.5">status</div>
                <div className="flex flex-wrap gap-1">
                  {r.rdap.status.map((s, i) => (
                    <span key={i} className="font-mono text-[11px] text-dim">{s}{i < r.rdap!.status!.length - 1 ? "," : ""}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="text-sm text-dim">RDAP not available for this TLD.</div>
        )}
      </div>

      <div>
        <div className="text-xs uppercase tracking-[0.16em] text-dim mb-3">email &amp; dnssec</div>
        <div className="surface divide-y divide-border/40">
          <SecRow ok={r.email.mxAdvertised > 0} label="mx"
            detail={r.email.mxAdvertised > 0 ? `${r.email.mxAdvertised} record${r.email.mxAdvertised === 1 ? "" : "s"} — accepts mail` : "no MX — domain does not accept mail"} />
          <SecRow ok={!!r.email.spf} label="spf"
            detail={r.email.spf ?? "no SPF — anyone can spoof mail From: this domain"} mono />
          <SecRow ok={!!r.email.dmarc} label="dmarc"
            detail={r.email.dmarc ?? "no _dmarc TXT — receivers won't enforce alignment"} mono />
          <SecRow ok={r.dnssec} label="dnssec"
            detail={r.dnssec ? "AD bit set — chain validates" : "zone unsigned or chain broken"} />
        </div>
      </div>
    </div>
  );
}

function KV({ k, v, hint, accent }: { k: string; v: string; hint?: string; accent?: "ok" | "warn" | "bad" }) {
  const color = accent === "bad" ? "text-amber-300" : accent === "warn" ? "text-amber-300/80" : "text-text";
  return (
    <div className="px-4 py-2.5 grid grid-cols-[120px_1fr] items-baseline gap-3">
      <span className="text-[11px] uppercase tracking-wider text-dim font-mono">{k}</span>
      <span className={`font-mono text-sm ${color} flex items-baseline gap-2`}>
        {v}
        {hint && <span className="text-[11px] text-dim">{hint}</span>}
      </span>
    </div>
  );
}

function expiryAccent(dt: string): "ok" | "warn" | "bad" | undefined {
  const days = (new Date(dt).getTime() - Date.now()) / 86400000;
  if (days < 30) return "bad";
  if (days < 90) return "warn";
  return undefined;
}

function SecRow({ ok, label, detail, mono }: { ok: boolean; label: string; detail: string; mono?: boolean }) {
  return (
    <div className="px-4 py-3">
      <div className="flex items-baseline justify-between mb-1">
        <span className="font-mono text-sm">
          <span className={`${ok ? "text-brand" : "text-amber-300"} mr-2`}>{ok ? "✓" : "✗"}</span>
          {label}
        </span>
        <span className={`font-mono text-[10px] uppercase tracking-wider ${ok ? "text-brand/70" : "text-amber-300/80"}`}>{ok ? "ok" : "missing"}</span>
      </div>
      <div className={`text-xs text-dim leading-relaxed ${mono ? "font-mono break-all" : ""}`}>{detail}</div>
    </div>
  );
}
