"use client";

import { useState } from "react";

// Cloudflare DNS-over-HTTPS — JSON API, CORS-enabled.
const DOH = "https://cloudflare-dns.com/dns-query";

type Answer = { name: string; type: number; TTL: number; data: string };
type Result = {
  type: string;
  status: number;            // DNS rcode: 0=NOERROR, 2=SERVFAIL, 3=NXDOMAIN
  answers: Answer[];
  authority?: Answer[];
  error?: string;
};

const TYPES: { id: string; num: number; desc: string }[] = [
  { id: "A",     num: 1,    desc: "IPv4 addresses" },
  { id: "AAAA",  num: 28,   desc: "IPv6 addresses" },
  { id: "CNAME", num: 5,    desc: "canonical name (alias)" },
  { id: "MX",    num: 15,   desc: "mail servers" },
  { id: "TXT",   num: 16,   desc: "SPF, DKIM, DMARC, verification" },
  { id: "NS",    num: 2,    desc: "name servers (delegation)" },
  { id: "SOA",   num: 6,    desc: "zone authority" },
  { id: "CAA",   num: 257,  desc: "which CAs may issue certs" },
  { id: "SRV",   num: 33,   desc: "service location records" },
  { id: "PTR",   num: 12,   desc: "reverse DNS (use 1.2.3.4.in-addr.arpa)" },
];

const TYPE_NAME: Record<number, string> = Object.fromEntries(TYPES.map(t => [t.num, t.id]));

export default function HomePage() {
  const [domain, setDomain] = useState("github.com");
  const [enabled, setEnabled] = useState(new Set(["A", "AAAA", "MX", "TXT", "NS"]));
  const [results, setResults] = useState<Result[]>([]);
  const [loading, setLoading] = useState(false);

  async function go() {
    if (!domain.trim()) return;
    setLoading(true);
    const out: Result[] = [];
    for (const t of TYPES.filter((t) => enabled.has(t.id))) {
      try {
        const r = await fetch(`${DOH}?name=${encodeURIComponent(domain.trim())}&type=${t.num}`, {
          headers: { Accept: "application/dns-json" },
        });
        const j = await r.json();
        out.push({
          type: t.id,
          status: j.Status,
          answers: j.Answer ?? [],
          authority: j.Authority ?? [],
        });
      } catch (e: any) {
        out.push({ type: t.id, status: -1, answers: [], error: e.message });
      }
    }
    setResults(out);
    setLoading(false);
  }

  function toggle(t: string) {
    const n = new Set(enabled);
    if (n.has(t)) n.delete(t); else n.add(t);
    setEnabled(n);
  }

  return (
    <main className="min-h-screen">
      <header className="max-w-5xl mx-auto px-5 pt-10">
        <div className="text-xs uppercase tracking-[0.18em] text-dim mb-2">wfrz.eu · open source</div>
        <h1 className="text-4xl md:text-5xl font-extrabold leading-tight">
          DNS lookup<span className="text-brand">.</span>
        </h1>
        <p className="text-dim mt-3 max-w-2xl">
          Browser-only <code>dig</code>. Resolves through Cloudflare's public
          DNS-over-HTTPS endpoint (<code>1.1.1.1</code>). 10 record types, batched in
          one click.
        </p>
      </header>

      <section className="max-w-5xl mx-auto px-5 pt-6 pb-24 space-y-5">
        <div className="card p-5 space-y-3">
          <div className="flex gap-2">
            <input value={domain} onChange={(e) => setDomain(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && go()}
              className="input input-mono text-lg !py-3 flex-1"
              placeholder="example.com" spellCheck={false} autoFocus />
            <button onClick={go} disabled={loading} className="btn-brand">{loading ? "…" : "Lookup"}</button>
          </div>
          <div>
            <div className="text-xs uppercase tracking-wider text-dim mb-1.5">Record types</div>
            <div className="flex flex-wrap gap-1.5">
              {TYPES.map(t => (
                <button key={t.id} onClick={() => toggle(t.id)} title={t.desc}
                  className={`chip ${enabled.has(t.id) ? "chip-on" : ""}`}>
                  {t.id}
                </button>
              ))}
            </div>
          </div>
        </div>

        {results.length > 0 && (
          <div className="space-y-3">
            {results.map((r) => (
              <div key={r.type} className="card overflow-hidden">
                <div className="p-3 border-b border-border/60 flex items-center justify-between">
                  <div className="flex items-baseline gap-3">
                    <code className="text-brand font-bold">{r.type}</code>
                    <span className="text-xs text-dim">{TYPES.find(t => t.id === r.type)?.desc}</span>
                  </div>
                  <div className="text-xs">
                    {r.status === 0 && r.answers.length > 0 && <span className="text-brand">{r.answers.length} record{r.answers.length === 1 ? "" : "s"}</span>}
                    {r.status === 0 && r.answers.length === 0 && <span className="text-dim">no records</span>}
                    {r.status === 3 && <span className="text-amber-300">NXDOMAIN</span>}
                    {r.status > 0 && r.status !== 3 && <span className="text-red-300">rcode {r.status}</span>}
                    {r.error && <span className="text-red-300">err: {r.error}</span>}
                  </div>
                </div>
                {r.answers.length > 0 && (
                  <table className="w-full text-sm font-mono">
                    <thead className="text-xs text-dim">
                      <tr><th className="text-left px-3 py-2">Name</th><th className="text-left px-3 py-2">Data</th><th className="text-right px-3 py-2">TTL</th></tr>
                    </thead>
                    <tbody>
                      {r.answers.map((a, i) => (
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
            ))}
          </div>
        )}

        <details className="card p-5">
          <summary className="cursor-pointer text-sm font-semibold">About</summary>
          <div className="mt-3 text-sm text-dim space-y-2">
            <p>Resolves via <code className="text-brand">cloudflare-dns.com/dns-query</code>
              — Cloudflare's free public DoH endpoint. Same data your browser uses for
              its own DNS, just exposed as JSON. No tracking on our side, no logs.</p>
            <p>For reverse DNS, look up the <code>PTR</code> record at
              <code className="text-brand"> 4.3.2.1.in-addr.arpa</code> (note the reversed octets).</p>
          </div>
        </details>
      </section>

      <footer className="border-t border-border/70 py-8 text-sm text-dim">
        <div className="max-w-5xl mx-auto px-5 flex items-center justify-between flex-wrap gap-4">
          <div>Powered by Cloudflare DoH (1.1.1.1). No tracking.</div>
          <a href="https://github.com/WhiteFreezing/dns-wfrz" target="_blank" rel="noopener" className="hover:text-text">GitHub →</a>
        </div>
      </footer>
    </main>
  );
}
