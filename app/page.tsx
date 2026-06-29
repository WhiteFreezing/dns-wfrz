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
      {/* ── HERO ──────────────────────────────────────────────── */}
      <header className="max-w-5xl mx-auto px-5 pt-16 pb-8 text-center">
        <div className="inline-flex items-center gap-2 text-xs uppercase tracking-[0.22em] text-dim mb-4">
          <span className="w-8 h-px bg-gradient-to-r from-transparent to-brand" />
          <span>dns.wfrz.eu · open source recon</span>
          <span className="w-8 h-px bg-gradient-to-l from-transparent to-brand" />
        </div>
        <h1 className="text-5xl md:text-6xl font-extrabold leading-[1.05] tracking-tight">
          See <span className="text-brand">everything</span>
          <br />a domain leaks.
        </h1>
        <p className="text-dim mt-5 max-w-xl mx-auto">
          DNS records, topology graph, ASN+geo per IP, RDAP whois,
          subdomains from CT logs, email security, DNSSEC. One probe.
        </p>

        {/* search */}
        <div className="mt-8 max-w-xl mx-auto">
          <div className="relative">
            <div className="absolute inset-0 bg-brand/20 blur-2xl rounded-2xl" />
            <div className="relative flex gap-2 p-2 rounded-2xl bg-surface border border-border/70 shadow-2xl">
              <div className="flex items-center px-3 text-dim font-mono text-sm select-none">https://</div>
              <input
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && probe()}
                className="bg-transparent flex-1 outline-none font-mono text-lg placeholder:text-dim/60 py-2.5"
                placeholder="example.com"
                spellCheck={false}
                autoFocus
              />
              <button onClick={probe} disabled={!!loading} className="btn-brand !px-6 !py-2.5">
                {loading ? "…" : (<><span>Probe</span><span className="kbd ml-1">⏎</span></>)}
              </button>
            </div>
          </div>

          {/* example chips */}
          {!result && (
            <div className="flex justify-center items-center gap-2 mt-4 text-xs text-dim flex-wrap">
              <span>or try:</span>
              {["github.com", "cloudflare.com", "anthropic.com", "wfrz.eu"].map((d) => (
                <button key={d} onClick={() => { setDomain(d); setTimeout(probe, 0); }}
                  className="chip hover:!border-brand/50 hover:!text-brand font-mono">{d}</button>
              ))}
            </div>
          )}
        </div>
      </header>

      <section className="max-w-7xl mx-auto px-5 pb-24 space-y-6">

        {loading && (
          <div className="card p-5 flex items-center gap-3">
            <span className="w-2.5 h-2.5 bg-brand rounded-full pulse-dot" />
            <div className="font-mono text-sm text-dim">{loading}</div>
          </div>
        )}

        {result && (
          <>
            <SummaryBar r={result} />

            {/* tabs */}
            <div className="flex gap-1 p-1.5 rounded-xl bg-surface/60 border border-border/70 backdrop-blur-sm w-fit max-w-full overflow-x-auto">
              <SectionTab on={section === "topology"} onClick={() => setSection("topology")} icon="🗺">Topology</SectionTab>
              <SectionTab on={section === "records"}  onClick={() => setSection("records")} icon="📋">Records</SectionTab>
              <SectionTab on={section === "ips"}      onClick={() => setSection("ips")} icon="🌐">IPs &amp; ASN</SectionTab>
              <SectionTab on={section === "subs"}     onClick={() => setSection("subs")} icon="🔎">
                Subdomains
                {result.subdomains.length > 0 && <span className="ml-1.5 px-1.5 py-0.5 text-[10px] rounded bg-brand/15 text-brand font-mono">{result.subdomains.length}</span>}
              </SectionTab>
              <SectionTab on={section === "whois"}    onClick={() => setSection("whois")} icon="🛡">WHOIS &amp; Email</SectionTab>
            </div>

            {section === "topology" && <Topology r={result} />}
            {section === "records"  && <RecordsView r={result} />}
            {section === "ips"      && <IpsView r={result} />}
            {section === "subs"     && <SubsView r={result} />}
            {section === "whois"    && <WhoisView r={result} />}
          </>
        )}
      </section>

      <footer className="border-t border-border/70 py-8 text-sm text-dim relative">
        <div className="max-w-7xl mx-auto px-5 flex items-center justify-between flex-wrap gap-4">
          <div className="font-mono text-xs">cloudflare-doh · ripestat · crt.sh · rdap — no auth, no tracking</div>
          <a href="https://github.com/WhiteFreezing/dns-wfrz" target="_blank" rel="noopener" className="hover:text-text inline-flex items-center gap-1.5">
            github
            <span>→</span>
          </a>
        </div>
      </footer>
    </main>
  );
}

// ── country flag emoji from ISO-3166 alpha-2 ─────────────────────
function flag(country?: string): string {
  if (!country || country.length !== 2) return "";
  return String.fromCodePoint(
    ...[...country.toUpperCase()].map((c) => 0x1F1E6 + c.charCodeAt(0) - 65)
  );
}

function unq(s: string) { return s.startsWith('"') && s.endsWith('"') ? s.slice(1, -1).replace(/"\s+"/g, "") : s; }

function SectionTab({ on, onClick, children, icon }: { on: boolean; onClick: () => void; children: React.ReactNode; icon?: string }) {
  return (
    <button onClick={onClick}
      className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold whitespace-nowrap transition ${
        on
          ? "bg-brand text-ink shadow-[0_4px_16px_-4px_rgba(249,115,22,.5)]"
          : "text-dim hover:text-text hover:bg-muted/60"
      }`}>
      {icon && <span className="text-base leading-none">{icon}</span>}
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
  const countries = new Set(Object.values(r.ips).map((i) => i.country).filter(Boolean));

  return (
    <div className="card p-5">
      <div className="flex items-start justify-between flex-wrap gap-4 mb-4">
        <div>
          <div className="text-xs uppercase tracking-wider text-dim mb-1">probed</div>
          <div className="font-mono text-2xl md:text-3xl font-extrabold text-brand">{r.domain}</div>
          {getRegistrar(r.rdap) && (
            <div className="text-sm text-dim mt-1">
              via <span className="text-text">{getRegistrar(r.rdap)}</span>
            </div>
          )}
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full font-mono font-semibold ${r.dnssec ? "bg-brand/15 text-brand border border-brand/30" : "bg-amber-500/10 text-amber-300 border border-amber-500/30"}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${r.dnssec ? "bg-brand" : "bg-amber-300"}`} />
            DNSSEC {r.dnssec ? "signed" : "off"}
          </span>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Stat icon="🕒" label="Age"         value={ageYears ? `${ageYears.toFixed(1)}` : "—"}    unit={ageYears ? "years" : ""} />
        <Stat icon="🌍" label="Nameservers" value={String(nsCount)}                              unit={nsCount === 1 ? "server" : "servers"} accent={nsCount >= 2 ? "ok" : "warn"} />
        <Stat icon="🖥"  label="IPs"         value={String(ipCount)}                              unit={ipCount === 1 ? "host" : "hosts"} />
        <Stat icon="📧" label="Mail (MX)"   value={String(mxCount)}                              unit={mxCount === 1 ? "record" : "records"} accent={mxCount > 0 ? undefined : "warn"} />
        <Stat icon="🌐" label="Countries"   value={String(countries.size)}                       unit={[...countries].join(" ")} />
      </div>
    </div>
  );
}

function Stat({ icon, label, value, unit, accent }: { icon: string; label: string; value: string; unit?: string; accent?: "ok" | "warn" }) {
  return (
    <div className="relative rounded-xl bg-muted/40 border border-border/60 px-4 py-3 hover:border-border transition">
      <div className="flex items-center gap-1.5 mb-1">
        <span className="text-sm grayscale opacity-70">{icon}</span>
        <span className="text-[10px] uppercase tracking-wider text-dim font-semibold">{label}</span>
      </div>
      <div className="flex items-baseline gap-1.5">
        <span className={`text-2xl font-extrabold tabular-nums ${accent === "ok" ? "text-brand" : accent === "warn" ? "text-amber-300" : "text-text"}`}>{value}</span>
        {unit && <span className="text-xs text-dim truncate font-mono">{unit}</span>}
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
    <div className="card p-5">
      <div className="flex items-center justify-between mb-4 flex-wrap gap-3">
        <div>
          <div className="text-xs uppercase tracking-[0.18em] text-dim mb-1">network topology</div>
          <div className="text-sm text-dim">
            Live infrastructure map. Hover any card for full hostname / IP.
          </div>
        </div>
        <div className="flex gap-2 flex-wrap text-xs">
          {groupsPresent.map((k) => (
            <span key={k}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md font-semibold border"
              style={{ borderColor: COLORS[k] + "55", background: COLORS[k] + "0d", color: COLORS[k] }}>
              <span className="w-1.5 h-1.5 rounded-full" style={{ background: COLORS[k] }} />
              {LABELS[k]}
            </span>
          ))}
        </div>
      </div>

      <div className="overflow-x-auto rounded-xl bg-gradient-to-br from-[#0b0d11] to-[#13161b] border border-border/60 relative">
        {/* subtle grid pattern */}
        <div className="absolute inset-0 opacity-[0.08] pointer-events-none"
          style={{ backgroundImage: "radial-gradient(#e8eaef 1px, transparent 1px)", backgroundSize: "20px 20px" }} />

        <div className="relative" style={{ width: W, height: H, minWidth: 900 }}>
          {/* SVG connectors below the cards */}
          <svg className="absolute inset-0 pointer-events-none" viewBox={`0 0 ${W} ${H}`}
               width={W} height={H}>
            <defs>
              {(Object.keys(COLORS) as TopoNode["kind"][]).map((k) => (
                <linearGradient key={k} id={`grad-${k}`} gradientUnits="userSpaceOnUse"
                  x1={domainCx} y1={domainCy} x2={W} y2={H}>
                  <stop offset="0%" stopColor="#f97316" stopOpacity="0.9" />
                  <stop offset="100%" stopColor={COLORS[k]} stopOpacity="0.7" />
                </linearGradient>
              ))}
            </defs>
            {allNodes.map((n) => (
              <g key={"p:" + n.id}>
                <path d={connectorPath(n)} fill="none"
                  stroke={`url(#grad-${n.kind})`} strokeWidth="2"
                  className="connector-flow" strokeLinecap="round" />
              </g>
            ))}
          </svg>

          {/* group labels */}
          {nsNodes.length > 0 && (
            <SectionLabel x={W / 2} y={6}    color={COLORS.ns}    text="NAMESERVERS" count={nsNodes.length} />
          )}
          {webNodes.length > 0 && (
            <SectionLabel x={webX + WEB_W / 2}  y={webStartY - 24} color={COLORS.web}   text="WEB" count={webNodes.length} />
          )}
          {mxNodes.length > 0 && (
            <SectionLabel x={30 + MX_W / 2}   y={mxStartY - 24}  color={COLORS.mx}    text="MAIL" count={mxNodes.length} />
          )}
          {cnNodes.length > 0 && (
            <SectionLabel x={W / 2} y={cnY - 24} color={COLORS.cname} text="CNAME" count={cnNodes.length} />
          )}

          {/* domain card — center hero */}
          <div className="absolute"
            style={{ left: domain.x, top: domain.y, width: domain.w, height: domain.h }}>
            <div className="absolute -inset-3 bg-brand/30 blur-2xl rounded-2xl" />
            <div className="relative h-full rounded-xl border border-brand/70 flex flex-col items-center justify-center"
              style={{ background: "linear-gradient(135deg, rgba(249,115,22,0.18), rgba(19,22,27,0.95))" }}>
              <div className="text-[10px] uppercase tracking-[0.25em] text-brand/80 font-mono font-semibold">DOMAIN</div>
              <div className="text-brand text-xl font-extrabold font-mono mt-1.5 truncate px-3 max-w-full">{r.domain}</div>
              <div className="text-[10px] text-dim mt-1 font-mono">
                {allNodes.length} edge{allNodes.length === 1 ? "" : "s"}
              </div>
            </div>
          </div>

          {/* all other nodes */}
          {allNodes.map((n) => (
            <NodeCard
              key={n.id} n={n} color={COLORS[n.kind]}
              countryCode={n.ip ? r.ips[n.ip]?.country : undefined}
            />
          ))}
        </div>
      </div>

      {allNodes.length === 0 && (
        <div className="text-sm text-dim text-center py-8">
          No records to graph for <code className="text-brand">{r.domain}</code>.
        </div>
      )}
    </div>
  );
}

function SectionLabel({ x, y, color, text, count }: { x: number; y: number; color: string; text: string; count: number }) {
  return (
    <div className="absolute -translate-x-1/2 flex items-center gap-2" style={{ left: x, top: y }}>
      <span className="font-mono uppercase text-[10px] tracking-[0.25em] font-semibold" style={{ color }}>{text}</span>
      <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded"
        style={{ background: color + "1a", color }}>{count}</span>
    </div>
  );
}

function NodeCard({ n, color, countryCode }: { n: TopoNode; color: string; countryCode?: string }) {
  const isPill = n.kind === "ns" || n.kind === "cname";
  return (
    <div className="absolute rounded-lg border bg-surface group transition hover:scale-[1.03] hover:!border-text hover:shadow-2xl hover:z-10"
      style={{
        left: n.x, top: n.y, width: n.w, height: n.h,
        borderColor: color + "55",
        background: `linear-gradient(135deg, ${color}0a, rgba(19,22,27,0.95))`,
      }}
      title={n.ip ? `${n.title} → ${n.ip}` : n.title}>
      {isPill ? (
        <div className="px-3 py-2.5 h-full flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: color }} />
          <span className="font-mono text-xs text-text truncate">{n.title}</span>
        </div>
      ) : (
        <div className="p-2.5 h-full flex flex-col justify-between">
          <div className="flex items-start gap-2">
            {n.badge && (
              <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded shrink-0 leading-tight"
                style={{ background: color + "22", color }}>
                {n.badge}
              </span>
            )}
            <span className="font-mono text-[13px] font-semibold text-text leading-tight break-all line-clamp-2">
              {n.title}
            </span>
            {countryCode && (
              <span className="ml-auto text-base leading-none shrink-0" title={countryCode}>{flag(countryCode)}</span>
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

const RECORD_COLORS: Record<RecordType, string> = {
  A: "#34d399", AAAA: "#34d399", CNAME: "#fbbf24",
  MX: "#a78bfa", TXT: "#fb7185", NS: "#22d3ee",
  SOA: "#94a3b8", CAA: "#22d3ee", SRV: "#a78bfa", DNSKEY: "#f97316",
};

function RecordsView({ r }: { r: Result }) {
  // Surface only the record types that actually returned something. The rest
  // would just be empty cards making the page longer for no reason.
  const present = RECORD_TYPES.filter((rt) => (r.records[rt.id]?.length ?? 0) > 0);
  const empty = RECORD_TYPES.filter((rt) => !(r.records[rt.id]?.length));

  return (
    <div className="space-y-4">
      {present.map((rt) => {
        const ans = r.records[rt.id] ?? [];
        const color = RECORD_COLORS[rt.id];
        return (
          <div key={rt.id} className="card overflow-hidden">
            <div className="px-5 py-3 border-b border-border/60 flex items-center justify-between"
              style={{ borderTop: `2px solid ${color}` }}>
              <div className="flex items-center gap-3">
                <code className="text-base font-extrabold font-mono" style={{ color }}>{rt.id}</code>
                <span className="text-xs text-dim font-mono">
                  {ans.length} {ans.length === 1 ? "record" : "records"}
                </span>
              </div>
              <a className="text-xs text-dim hover:text-text"
                href={`https://cloudflare-dns.com/dns-query?name=${r.domain}&type=${rt.num}&do=true`}
                target="_blank" rel="noopener">raw DoH ↗</a>
            </div>
            <div className="divide-y divide-border/40">
              {ans.map((a, i) => (
                <div key={i} className="px-5 py-3 grid grid-cols-[1fr_auto] gap-3 items-start hover:bg-muted/30 transition">
                  <code className="text-sm font-mono break-all leading-relaxed">{a.data}</code>
                  <span className="text-[10px] uppercase tracking-wider text-dim font-mono whitespace-nowrap mt-0.5">TTL {a.TTL}s</span>
                </div>
              ))}
            </div>
          </div>
        );
      })}

      {empty.length > 0 && (
        <div className="card-flat p-4">
          <div className="text-xs uppercase tracking-wider text-dim mb-2">No records for</div>
          <div className="flex flex-wrap gap-1.5">
            {empty.map((rt) => (
              <span key={rt.id} className="px-2 py-1 rounded text-xs font-mono bg-muted/50 text-dim border border-border/40">{rt.id}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── IPs VIEW ─────────────────────────────────────────────────────

function IpsView({ r }: { r: Result }) {
  const ips = Object.values(r.ips);
  if (!ips.length) return <div className="card p-5 text-sm text-dim">No IPs to analyze.</div>;

  // Group by ASN holder to surface "this domain is hosted on X" at a glance.
  const byHolder = new Map<string, IpInfo[]>();
  ips.forEach((ip) => {
    const key = ip.holder ?? "Unknown";
    if (!byHolder.has(key)) byHolder.set(key, []);
    byHolder.get(key)!.push(ip);
  });

  return (
    <div className="space-y-5">
      {[...byHolder.entries()].map(([holder, group]) => (
        <div key={holder} className="card overflow-hidden">
          <div className="px-5 py-3 border-b border-border/60 flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-3">
              <span className="text-2xl leading-none">{flag(group[0]?.country) || "🌐"}</span>
              <div>
                <div className="font-bold">{holder}</div>
                <div className="text-xs text-dim font-mono">
                  {group[0]?.asn ?? ""} {group[0]?.country ? "· " + group[0].country : ""} {group[0]?.city ? "· " + group[0].city : ""}
                </div>
              </div>
            </div>
            <div className="text-sm text-dim">
              {group.length} {group.length === 1 ? "IP" : "IPs"}
            </div>
          </div>
          <div className="divide-y divide-border/40">
            {group.map((ip) => (
              <div key={ip.ip} className="px-5 py-3 flex items-center justify-between gap-4 flex-wrap hover:bg-muted/30 transition">
                <div className="flex items-center gap-3 min-w-0">
                  <code className="font-mono text-brand font-bold text-base break-all">{ip.ip}</code>
                  {ip.prefix && (
                    <code className="text-[11px] text-dim font-mono px-1.5 py-0.5 rounded bg-muted border border-border/60">
                      {ip.prefix}
                    </code>
                  )}
                </div>
                <div className="flex gap-1.5 text-[11px]">
                  {ip.lat !== undefined && (
                    <a className="chip" target="_blank" rel="noopener"
                      href={`https://www.openstreetmap.org/?mlat=${ip.lat}&mlon=${ip.lon}&zoom=8`}>map ↗</a>
                  )}
                  <a className="chip" target="_blank" rel="noopener" href={`https://bgp.he.net/ip/${ip.ip}`}>HE ↗</a>
                  <a className="chip" target="_blank" rel="noopener" href={`https://stat.ripe.net/${ip.ip}`}>RIPE ↗</a>
                  <a className="chip" target="_blank" rel="noopener" href={`https://www.shodan.io/host/${ip.ip}`}>Shodan ↗</a>
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
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
    <div className="card p-8 text-center text-dim space-y-2">
      <div className="text-4xl opacity-30">🔍</div>
      <p className="text-sm">No subdomains found in Certificate Transparency logs.</p>
      <p className="text-xs">Either the domain hasn't ever issued a public TLS cert, or crt.sh is slow.</p>
    </div>
  );

  return (
    <div className="space-y-4">
      <div className="card p-5 flex items-center justify-between gap-4 flex-wrap">
        <div>
          <div className="text-[10px] uppercase tracking-wider text-dim mb-1">discovered subdomains</div>
          <div className="flex items-baseline gap-3">
            <span className="text-brand font-extrabold text-4xl tabular-nums">{r.subdomains.length}</span>
            <span className="text-xs text-dim">via Certificate Transparency</span>
          </div>
        </div>
        <div className="flex gap-2 items-center">
          <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="filter…"
            className="input input-mono text-sm w-48" />
          <a className="chip" target="_blank" rel="noopener" href={`https://crt.sh/?q=%25.${r.domain}`}>raw crt.sh ↗</a>
        </div>
      </div>

      <div className="card p-4">
        {filter && subs.length !== r.subdomains.length && (
          <div className="text-xs text-dim mb-2">{subs.length} of {r.subdomains.length} matching</div>
        )}
        <div className="grid sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-1.5">
          {subs.map((s) => {
            const prefix = s.replace("." + r.domain, "");
            return (
              <a key={s} target="_blank" rel="noopener" href={`https://${s}`}
                className="group px-2.5 py-1.5 rounded-lg bg-muted/40 border border-border/50 hover:border-brand/60 hover:bg-brand/5 transition truncate font-mono text-xs flex items-center gap-1.5">
                <span className="text-brand">{prefix}</span>
                <span className="text-dim group-hover:text-text/50 text-[10px]">.{r.domain}</span>
              </a>
            );
          })}
        </div>
        <p className="text-xs text-dim mt-4 leading-relaxed">
          CT logs every public TLS certificate that's ever been issued — Let's Encrypt + paid CAs all submit.
          Catches forgotten staging hosts, internal dashboards exposed by accident, abandoned services.
        </p>
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
    <div className="grid md:grid-cols-2 gap-4">
      <div className="card overflow-hidden">
        <div className="px-5 py-3 border-b border-border/60 flex items-center gap-2"
          style={{ borderTop: "2px solid #22d3ee" }}>
          <span className="text-base">📜</span>
          <div className="text-xs uppercase tracking-[0.18em] text-dim font-semibold">Registration (RDAP)</div>
        </div>
        {r.rdap ? (
          <div className="p-5 space-y-4">
            {registrar && (
              <div>
                <div className="text-xs uppercase tracking-wider text-dim mb-1">Registrar</div>
                <div className="text-lg font-bold">{registrar}</div>
              </div>
            )}
            <div className="grid grid-cols-3 gap-3">
              <DateBlock label="Registered" date={reg?.eventDate} />
              <DateBlock label="Updated"    date={upd?.eventDate} />
              <DateBlock label="Expires"    date={exp?.eventDate}
                hint={daysToExpiry !== null ? `${daysToExpiry} d` : undefined}
                accent={exp ? expiryAccent(exp.eventDate) : undefined} />
            </div>
            {r.rdap.status && r.rdap.status.length > 0 && (
              <div>
                <div className="text-xs uppercase tracking-wider text-dim mb-2">Status flags</div>
                <div className="flex flex-wrap gap-1.5">
                  {r.rdap.status.map((s, i) => (
                    <span key={i} className="px-2 py-0.5 rounded text-[11px] font-mono bg-muted border border-border/60 text-dim">{s}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="p-5 text-sm text-dim">RDAP not available for this TLD or registry.</div>
        )}
      </div>

      <div className="card overflow-hidden">
        <div className="px-5 py-3 border-b border-border/60 flex items-center gap-2"
          style={{ borderTop: "2px solid #fb7185" }}>
          <span className="text-base">🛡</span>
          <div className="text-xs uppercase tracking-[0.18em] text-dim font-semibold">Email security &amp; DNSSEC</div>
        </div>
        <div className="p-5 space-y-2">
          <SecRow ok={r.email.mxAdvertised > 0} label="MX records"
            detail={r.email.mxAdvertised > 0 ? `${r.email.mxAdvertised} record${r.email.mxAdvertised === 1 ? "" : "s"} advertised — domain accepts mail` : "no MX — domain does not accept mail"} />
          <SecRow ok={!!r.email.spf} label="SPF"
            detail={r.email.spf ?? "no SPF — anyone can spoof mail From: this domain"} mono />
          <SecRow ok={!!r.email.dmarc} label="DMARC"
            detail={r.email.dmarc ?? "no _dmarc TXT — receivers won't enforce alignment"} mono />
          <SecRow ok={r.dnssec} label="DNSSEC"
            detail={r.dnssec ? "AD bit set on response — chain validates" : "zone unsigned or chain broken"} />
        </div>
      </div>
    </div>
  );
}

function DateBlock({ label, date, hint, accent }: { label: string; date?: string; hint?: string; accent?: "ok" | "warn" | "bad" }) {
  const color = accent === "bad" ? "text-red-300" : accent === "warn" ? "text-amber-300" : "text-text";
  return (
    <div className="rounded-lg bg-muted/40 border border-border/60 p-3">
      <div className="text-[10px] uppercase tracking-wider text-dim mb-1">{label}</div>
      <div className={`font-mono font-semibold text-sm ${color}`}>{date?.slice(0, 10) ?? "—"}</div>
      {hint && <div className={`text-[10px] font-mono ${color} opacity-80`}>{hint}</div>}
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
    <div className={`rounded-lg p-3 border ${ok ? "bg-brand/5 border-brand/30" : "bg-red-500/5 border-red-500/25"}`}>
      <div className="flex items-center justify-between mb-1">
        <span className="font-semibold text-sm flex items-center gap-2">
          <span className={`w-1.5 h-1.5 rounded-full ${ok ? "bg-brand" : "bg-red-300"}`} />
          {label}
        </span>
        <span className={`text-[11px] font-mono font-bold ${ok ? "text-brand" : "text-red-300"}`}>{ok ? "PASS" : "FAIL"}</span>
      </div>
      <div className={`text-xs text-dim leading-relaxed ${mono ? "font-mono break-all" : ""}`}>{detail}</div>
    </div>
  );
}
