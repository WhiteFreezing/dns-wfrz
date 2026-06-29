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
    const dohJobs = RECORD_TYPES.map(async (rt) => {
      const r = await fetch(`${DOH}?name=${encodeURIComponent(d)}&type=${rt.num}&do=true`, {
        headers: { Accept: "application/dns-json" },
      });
      const j: DohResult = await r.json();
      return { id: rt.id, j };
    });
    const dohRes = await Promise.all(dohJobs);

    const records: Partial<Record<RecordType, Answer[]>> = {};
    const status: Partial<Record<RecordType, number>> = {};
    let dnssec = false;
    for (const { id, j } of dohRes) {
      records[id] = j.Answer ?? [];
      status[id] = j.Status;
      if (j.AD) dnssec = true;
    }

    // 2) DMARC at _dmarc.<domain>
    setLoading("Resolving DMARC…");
    try {
      const r = await fetch(`${DOH}?name=${encodeURIComponent("_dmarc." + d)}&type=16`, { headers: { Accept: "application/dns-json" } });
      const j: DohResult = await r.json();
      const dmarcRec = (j.Answer ?? []).find((a) => unq(a.data).startsWith("v=DMARC1"));
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
        mxTargets[host] = (j.Answer ?? []).map((a) => a.data);
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
      <header className="max-w-7xl mx-auto px-5 pt-10">
        <div className="text-xs uppercase tracking-[0.18em] text-dim mb-2">wfrz.eu · open source</div>
        <h1 className="text-4xl md:text-5xl font-extrabold leading-tight">
          DNS recon<span className="text-brand">.</span>
        </h1>
        <p className="text-dim mt-3 max-w-2xl">
          DNSDumpster-style domain intel — records, topology graph, CT-log subdomain
          enumeration, per-IP ASN + geo, RDAP whois, email security check, DNSSEC. All
          browser-side via public CORS APIs.
        </p>
      </header>

      <section className="max-w-7xl mx-auto px-5 pt-6 pb-24 space-y-5">
        <div className="card p-5 flex gap-2">
          <input value={domain} onChange={(e) => setDomain(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && probe()}
            className="input input-mono text-lg !py-3 flex-1"
            placeholder="example.com" spellCheck={false} autoFocus />
          <button onClick={probe} disabled={!!loading} className="btn-brand !px-6">
            {loading ? "…" : "Probe"}
          </button>
        </div>

        {loading && (
          <div className="card p-4 text-sm text-dim flex items-center gap-2">
            <span className="inline-block w-2 h-2 bg-brand rounded-full animate-pulse" />
            {loading}
          </div>
        )}

        {result && (
          <>
            <SummaryBar r={result} />

            <div className="card p-2 flex gap-1 flex-wrap">
              <SectionTab on={section === "topology"} onClick={() => setSection("topology")}>Topology</SectionTab>
              <SectionTab on={section === "records"}  onClick={() => setSection("records")}>Records</SectionTab>
              <SectionTab on={section === "ips"}      onClick={() => setSection("ips")}>IPs &amp; ASN</SectionTab>
              <SectionTab on={section === "subs"}     onClick={() => setSection("subs")}>Subdomains</SectionTab>
              <SectionTab on={section === "whois"}    onClick={() => setSection("whois")}>WHOIS &amp; Email</SectionTab>
            </div>

            {section === "topology" && <Topology r={result} />}
            {section === "records"  && <RecordsView r={result} />}
            {section === "ips"      && <IpsView r={result} />}
            {section === "subs"     && <SubsView r={result} />}
            {section === "whois"    && <WhoisView r={result} />}
          </>
        )}

        {!result && !loading && (
          <div className="card p-8 text-center text-dim space-y-2">
            <div className="text-5xl mb-3 opacity-30">🌐</div>
            <p>Enter a domain to start probing.</p>
            <div className="text-xs">Try: <button onClick={() => { setDomain("github.com"); setTimeout(probe, 0); }} className="text-brand underline">github.com</button> · <button onClick={() => { setDomain("anthropic.com"); setTimeout(probe, 0); }} className="text-brand underline">anthropic.com</button> · <button onClick={() => { setDomain("wfrz.eu"); setTimeout(probe, 0); }} className="text-brand underline">wfrz.eu</button></div>
          </div>
        )}
      </section>

      <footer className="border-t border-border/70 py-8 text-sm text-dim">
        <div className="max-w-7xl mx-auto px-5 flex items-center justify-between flex-wrap gap-4">
          <div>Data via Cloudflare DoH · RIPEstat · crt.sh · RDAP. No tracking, no auth.</div>
          <a href="https://github.com/WhiteFreezing/dns-wfrz" target="_blank" rel="noopener" className="hover:text-text">GitHub →</a>
        </div>
      </footer>
    </main>
  );
}

function unq(s: string) { return s.startsWith('"') && s.endsWith('"') ? s.slice(1, -1).replace(/"\s+"/g, "") : s; }

function SectionTab({ on, onClick, children }: { on: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button onClick={onClick}
      className={`px-4 py-2 rounded-md text-sm font-semibold transition ${on ? "bg-brand text-white" : "text-dim hover:text-text"}`}>
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

  return (
    <div className="grid grid-cols-2 md:grid-cols-6 gap-2">
      <Stat label="Domain"      value={r.domain} mono />
      <Stat label="Registrar"   value={getRegistrar(r.rdap) ?? "—"} />
      <Stat label="Age"         value={ageYears ? `${ageYears.toFixed(1)} yrs` : "—"} />
      <Stat label="Nameservers" value={String(nsCount)} accent={nsCount >= 2 ? "ok" : "warn"} />
      <Stat label="IPs"         value={String(ipCount)} />
      <Stat label="DNSSEC"      value={r.dnssec ? "signed" : "off"} accent={r.dnssec ? "ok" : "warn"} />
    </div>
  );
}

function Stat({ label, value, mono, accent }: { label: string; value: string; mono?: boolean; accent?: "ok" | "warn" }) {
  return (
    <div className="card p-3">
      <div className="text-[10px] uppercase tracking-wider text-dim">{label}</div>
      <div className={`text-base font-bold mt-1 truncate ${mono ? "font-mono" : ""} ${accent === "ok" ? "text-brand" : accent === "warn" ? "text-amber-300" : ""}`}>{value}</div>
    </div>
  );
}

function getRegistrar(rdap?: Rdap): string | undefined {
  const ent = rdap?.entities?.find((e) => e.roles?.includes("registrar"));
  const fn = ent?.vcardArray?.[1]?.find?.((v: any[]) => v[0] === "fn");
  return fn?.[3];
}

// ── TOPOLOGY SVG ─────────────────────────────────────────────────
// Pure-SVG radial layout. Center = domain. Four arcs around it for NS /
// A+AAAA / MX / CNAME. IPs branch out one more ring, labelled with ASN.
// No external graph lib — keeps the bundle slim.

function Topology({ r }: { r: Result }) {
  const W = 1100, H = 720;
  const cx = W / 2, cy = H / 2;

  // arrange groups around the center
  const groups: {
    label: string;
    color: string;
    items: { id: string; label: string; sub?: string; ip?: string }[];
    arc: [number, number]; // [start deg, end deg]
    ring: number;
  }[] = [];

  if (r.records.NS?.length) groups.push({
    label: "Nameservers", color: "#22d3ee", arc: [-110, -70], ring: 220,
    items: r.records.NS.map((a) => ({ id: "ns:" + a.data, label: a.data.replace(/\.$/, "") })),
  });
  if (r.records.A?.length || r.records.AAAA?.length) {
    const items = [
      ...(r.records.A ?? []).map((a) => ({ id: "a:" + a.data, label: a.data, sub: r.ips[a.data]?.holder, ip: a.data })),
      ...(r.records.AAAA ?? []).map((a) => ({ id: "aaaa:" + a.data, label: a.data, sub: r.ips[a.data]?.holder, ip: a.data })),
    ];
    groups.push({ label: "Web (A / AAAA)", color: "#34d399", arc: [-20, 20], ring: 220, items });
  }
  if (r.records.MX?.length) groups.push({
    label: "Mail (MX)", color: "#a78bfa", arc: [70, 110], ring: 220,
    items: r.records.MX.map((a) => {
      const parts = a.data.split(/\s+/);
      const host = parts.slice(1).join(" ").replace(/\.$/, "");
      const ips = r.mxTargets[host] || [];
      return { id: "mx:" + host, label: host, sub: ips[0] ? r.ips[ips[0]]?.holder : undefined, ip: ips[0] };
    }),
  });
  if (r.records.CNAME?.length) groups.push({
    label: "CNAME", color: "#fbbf24", arc: [160, 200], ring: 220,
    items: r.records.CNAME.map((a) => ({ id: "cn:" + a.data, label: a.data.replace(/\.$/, "") })),
  });

  // position items
  const positioned: { id: string; x: number; y: number; label: string; sub?: string; color: string; ip?: string; groupLabel: string }[] = [];
  groups.forEach((g) => {
    const n = g.items.length;
    g.items.forEach((it, i) => {
      const t = n === 1 ? 0.5 : i / (n - 1);
      const angleDeg = g.arc[0] + (g.arc[1] - g.arc[0]) * t;
      const a = (angleDeg * Math.PI) / 180;
      positioned.push({ ...it, x: cx + Math.cos(a) * g.ring, y: cy + Math.sin(a) * g.ring, color: g.color, groupLabel: g.label });
    });
  });

  return (
    <div className="card p-4">
      <div className="flex items-center justify-between mb-2">
        <div className="text-sm text-dim">
          Domain → nameservers, web hosts, mail servers, CNAME chain.
          Hover any node for detail.
        </div>
        <div className="flex gap-3 text-xs">
          {groups.map((g) => (
            <span key={g.label} className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full" style={{ background: g.color }} />
              <span className="text-dim">{g.label}</span>
            </span>
          ))}
        </div>
      </div>

      <div className="overflow-x-auto">
        <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ minWidth: 800 }}>
          {/* group arc labels */}
          {groups.map((g) => {
            const mid = (g.arc[0] + g.arc[1]) / 2;
            const a = (mid * Math.PI) / 180;
            const x = cx + Math.cos(a) * (g.ring + 60);
            const y = cy + Math.sin(a) * (g.ring + 60);
            return (
              <text key={g.label} x={x} y={y} textAnchor="middle" fill={g.color}
                fontSize="11" fontFamily="JetBrains Mono, monospace"
                style={{ textTransform: "uppercase", letterSpacing: 2 }}>
                {g.label.toUpperCase()}
              </text>
            );
          })}

          {/* edges from center to each node */}
          {positioned.map((p) => (
            <line key={"edge-" + p.id} x1={cx} y1={cy} x2={p.x} y2={p.y}
              stroke={p.color} strokeOpacity="0.35" strokeWidth="1.5" />
          ))}

          {/* center: domain */}
          <g>
            <circle cx={cx} cy={cy} r="58" fill="#13161b" stroke="#f97316" strokeWidth="2.5" />
            <text x={cx} y={cy - 4} textAnchor="middle" fill="#8b9099" fontSize="10"
              fontFamily="JetBrains Mono, monospace"
              style={{ textTransform: "uppercase", letterSpacing: 2 }}>
              DOMAIN
            </text>
            <text x={cx} y={cy + 14} textAnchor="middle" fill="#f97316"
              fontSize="14" fontWeight="800" fontFamily="JetBrains Mono, monospace">
              {truncate(r.domain, 16)}
            </text>
          </g>

          {/* nodes */}
          {positioned.map((p) => (
            <g key={p.id}>
              <title>{p.groupLabel}: {p.label}{p.sub ? ` — ${p.sub}` : ""}{p.ip ? ` (${p.ip})` : ""}</title>
              <circle cx={p.x} cy={p.y} r="9" fill={p.color} fillOpacity="0.2" stroke={p.color} strokeWidth="1.5" />
              <text x={p.x} y={p.y - 16} textAnchor="middle"
                fill="#e8eaef" fontSize="11" fontWeight="600" fontFamily="JetBrains Mono, monospace">
                {truncate(p.label, 28)}
              </text>
              {p.sub && (
                <text x={p.x} y={p.y + 22} textAnchor="middle" fill="#8b9099"
                  fontSize="10" fontFamily="Inter, sans-serif">
                  {truncate(p.sub, 30)}
                </text>
              )}
            </g>
          ))}
        </svg>
      </div>
    </div>
  );
}

function truncate(s: string, n: number) {
  if (n <= 0) return "";
  return s.length <= n ? s : s.slice(0, n - 1) + "…";
}

// ── RECORDS VIEW ─────────────────────────────────────────────────

function RecordsView({ r }: { r: Result }) {
  return (
    <div className="space-y-3">
      {RECORD_TYPES.map((rt) => {
        const ans = r.records[rt.id] ?? [];
        const st = r.status[rt.id];
        return (
          <div key={rt.id} className="card overflow-hidden">
            <div className="p-3 border-b border-border/60 flex items-center justify-between">
              <div className="flex items-baseline gap-3">
                <code className="text-brand font-bold">{rt.id}</code>
                <span className="text-xs text-dim">
                  {st === 0 ? (ans.length > 0 ? `${ans.length} record${ans.length === 1 ? "" : "s"}` : "no records") :
                   st === 3 ? "NXDOMAIN" : `rcode ${st}`}
                </span>
              </div>
            </div>
            {ans.length > 0 && (
              <table className="w-full text-sm font-mono">
                <thead className="text-xs text-dim">
                  <tr><th className="text-left px-3 py-2">Name</th><th className="text-left px-3 py-2">Data</th><th className="text-right px-3 py-2">TTL</th></tr>
                </thead>
                <tbody>
                  {ans.map((a, i) => (
                    <tr key={i} className="border-t border-border/40">
                      <td className="px-3 py-2 text-dim">{a.name}</td>
                      <td className="px-3 py-2 break-all">{a.data}</td>
                      <td className="px-3 py-2 text-dim text-right">{a.TTL}s</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── IPs VIEW ─────────────────────────────────────────────────────

function IpsView({ r }: { r: Result }) {
  const ips = Object.values(r.ips);
  if (!ips.length) return <div className="card p-5 text-sm text-dim">No IPs to analyze.</div>;
  return (
    <div className="grid md:grid-cols-2 gap-3">
      {ips.map((ip) => (
        <div key={ip.ip} className="card p-4">
          <div className="flex items-baseline justify-between mb-2">
            <code className="font-mono text-brand text-lg font-bold">{ip.ip}</code>
            <span className="text-xs text-dim">{ip.country ?? "??"}</span>
          </div>
          {ip.holder && <div className="text-sm font-semibold">{ip.holder}</div>}
          <div className="text-xs text-dim mt-2 grid grid-cols-2 gap-1">
            <div>ASN: <span className="text-text">{ip.asn ?? "—"}</span></div>
            <div>Prefix: <span className="text-text font-mono">{ip.prefix ?? "—"}</span></div>
            <div>City: <span className="text-text">{ip.city ?? "—"}</span></div>
            <div>Geo: {ip.lat !== undefined ? (
              <a className="text-brand hover:underline" target="_blank" rel="noopener"
                 href={`https://www.openstreetmap.org/?mlat=${ip.lat}&mlon=${ip.lon}&zoom=8`}>map ↗</a>
            ) : <span className="text-text">—</span>}</div>
          </div>
          <div className="mt-3 flex gap-1.5 text-[11px]">
            <a className="chip" target="_blank" rel="noopener" href={`https://bgp.he.net/ip/${ip.ip}`}>HE ↗</a>
            <a className="chip" target="_blank" rel="noopener" href={`https://stat.ripe.net/${ip.ip}`}>RIPEstat ↗</a>
            <a className="chip" target="_blank" rel="noopener" href={`https://www.shodan.io/host/${ip.ip}`}>Shodan ↗</a>
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
    <div className="card p-5 text-sm text-dim">
      No subdomains found via Certificate Transparency. Either the domain has no
      public TLS certs, or crt.sh is slow today.
    </div>
  );

  return (
    <div className="card p-5 space-y-3">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="text-sm">
          <span className="text-brand font-bold text-2xl">{r.subdomains.length}</span>
          <span className="text-dim ml-2">subdomain{r.subdomains.length === 1 ? "" : "s"} via Certificate Transparency</span>
        </div>
        <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="filter…"
          className="input input-mono text-sm max-w-xs" />
      </div>
      <div className="grid sm:grid-cols-2 md:grid-cols-3 gap-1.5 font-mono text-xs">
        {subs.map((s) => (
          <a key={s} target="_blank" rel="noopener" href={`https://${s}`}
            className="px-2.5 py-1.5 rounded bg-muted border border-border hover:border-brand hover:text-brand transition truncate">
            {s}
          </a>
        ))}
      </div>
      <div className="text-xs text-dim">
        Source: <a className="text-brand hover:underline" target="_blank" rel="noopener" href={`https://crt.sh/?q=%25.${r.domain}`}>crt.sh ↗</a>.
        CT logs every cert ever issued — only catches names that got a public cert (Let's Encrypt + paid CAs alike).
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

  return (
    <div className="grid md:grid-cols-2 gap-3">
      <div className="card p-5 space-y-3">
        <div className="text-xs uppercase tracking-wider text-dim">Registration (RDAP)</div>
        {r.rdap ? (
          <div className="space-y-2 text-sm">
            <KV k="Registrar" v={registrar ?? "—"} />
            <KV k="Registered" v={reg?.eventDate?.slice(0, 10) ?? "—"} />
            <KV k="Expires"    v={exp?.eventDate?.slice(0, 10) ?? "—"} accent={
              exp ? expiryAccent(exp.eventDate) : undefined
            } />
            <KV k="Last update" v={upd?.eventDate?.slice(0, 10) ?? "—"} />
            <KV k="Status" v={r.rdap.status?.join(", ") ?? "—"} small />
          </div>
        ) : (
          <div className="text-sm text-dim">RDAP not available for this TLD or registry.</div>
        )}
      </div>

      <div className="card p-5 space-y-3">
        <div className="text-xs uppercase tracking-wider text-dim">Email security</div>
        <div className="space-y-3 text-sm">
          <SecRow ok={r.email.mxAdvertised > 0} label="MX records present"
            detail={`${r.email.mxAdvertised} MX record${r.email.mxAdvertised === 1 ? "" : "s"} advertised`} />
          <SecRow ok={!!r.email.spf} label="SPF" detail={r.email.spf ?? "no SPF record — anyone can spoof mail from this domain"} mono />
          <SecRow ok={!!r.email.dmarc} label="DMARC" detail={r.email.dmarc ?? "no _dmarc TXT — receivers won't enforce alignment"} mono />
          <SecRow ok={r.dnssec} label="DNSSEC" detail={r.dnssec ? "AD bit set on response — chain validates" : "AD bit not set — zone unsigned or chain broken"} />
        </div>
      </div>
    </div>
  );
}

function KV({ k, v, small, accent }: { k: string; v: string; small?: boolean; accent?: "ok" | "warn" | "bad" }) {
  return (
    <div className="flex items-baseline gap-2">
      <span className="text-xs text-dim w-28 shrink-0">{k}</span>
      <span className={`flex-1 ${small ? "text-xs" : ""} ${accent === "warn" ? "text-amber-300" : accent === "bad" ? "text-red-300" : ""} font-mono`}>{v}</span>
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
    <div className={`rounded-lg p-3 border ${ok ? "bg-brand/10 border-brand/40" : "bg-red-500/5 border-red-500/30"}`}>
      <div className="flex items-center justify-between mb-1">
        <span className="font-semibold">{label}</span>
        <span className={`text-xs font-semibold ${ok ? "text-brand" : "text-red-300"}`}>{ok ? "✓ ok" : "✗ missing"}</span>
      </div>
      <div className={`text-xs text-dim ${mono ? "font-mono break-all" : ""}`}>{detail}</div>
    </div>
  );
}
