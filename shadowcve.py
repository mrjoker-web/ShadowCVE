#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════╗
║           ShadowCVE - by Mr. Joker            ║
║         Shadow Suite · github.com/mrjoker-web  ║
║     CVE Intelligence Tool for Pentesters       ║
╚═══════════════════════════════════════════════╝
"""

import argparse
import json
import sys
import os
import datetime
import urllib.request
import urllib.parse
import urllib.error

# ─────────────────────────────────────────────────────────
# CORES
# ─────────────────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    MAGENTA = "\033[95m"
    DIM     = "\033[2m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

# ─────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────
BANNER = f"""
{C.RED}{C.BOLD}
 ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗ ██████╗██╗   ██╗███████╗
 ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔════╝██║   ██║██╔════╝
 ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║██║     ██║   ██║█████╗  
 ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██║     ╚██╗ ██╔╝██╔══╝  
 ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝╚██████╗ ╚████╔╝ ███████╗
 ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝  ╚═════╝  ╚═══╝  ╚══════╝
{C.RESET}
{C.DIM}         CVE Intelligence Tool · by Mr. Joker · Shadow Suite{C.RESET}
{C.DIM}         Uso exclusivamente educacional e em ambientes autorizados{C.RESET}
"""

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXPLOITDB_SEARCH = "https://www.exploit-db.com/search?cve="

CVSS_COLORS = {
    "CRITICAL": C.RED,
    "HIGH":     C.YELLOW,
    "MEDIUM":   C.MAGENTA,
    "LOW":      C.GREEN,
    "NONE":     C.DIM,
}

# ─────────────────────────────────────────────────────────
# UTILITÁRIOS
# ─────────────────────────────────────────────────────────
def separator(title=""):
    width = 60
    if title:
        pad = (width - len(title) - 2) // 2
        print(f"\n{C.DIM}{'─' * pad} {C.CYAN}{C.BOLD}{title}{C.RESET}{C.DIM} {'─' * pad}{C.RESET}")
    else:
        print(f"{C.DIM}{'─' * width}{C.RESET}")

def severity_color(score):
    try:
        s = float(score)
        if s >= 9.0: return "CRITICAL", C.RED
        if s >= 7.0: return "HIGH",     C.YELLOW
        if s >= 4.0: return "MEDIUM",   C.MAGENTA
        if s > 0.0:  return "LOW",      C.GREEN
    except:
        pass
    return "NONE", C.DIM

def fetch_nvd(params: dict):
    query = urllib.parse.urlencode(params)
    url = f"{NVD_BASE}?{query}"
    req = urllib.request.Request(url, headers={"User-Agent": "ShadowCVE/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        print(f"{C.RED}[!] Erro HTTP {e.code} na NVD API{C.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{C.RED}[!] Erro de ligação: {e}{C.RESET}")
        sys.exit(1)

def extract_cvss(cve_item):
    metrics = cve_item.get("metrics", {})
    # Tenta CVSSv3.1 → v3.0 → v2
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            data = m.get("cvssData", {})
            score = data.get("baseScore", "N/A")
            severity = data.get("baseSeverity", m.get("baseSeverity", "N/A"))
            vector = data.get("vectorString", "N/A")
            version = data.get("version", key.replace("cvssMetricV", ""))
            return score, severity, vector, f"CVSSv{version}"
    return "N/A", "N/A", "N/A", "N/A"

def extract_description(cve_item):
    for desc in cve_item.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "Sem descrição disponível.")
    return "Sem descrição disponível."

def extract_references(cve_item):
    refs = cve_item.get("references", [])
    return [r.get("url", "") for r in refs[:5]]

def extract_weaknesses(cve_item):
    cwes = []
    for w in cve_item.get("weaknesses", []):
        for desc in w.get("description", []):
            val = desc.get("value", "")
            if val and val != "NVD-CWE-Other":
                cwes.append(val)
    return cwes

# ─────────────────────────────────────────────────────────
# PRINT CVE
# ─────────────────────────────────────────────────────────
def print_cve(item, verbose=True):
    cve = item.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")
    published = cve.get("published", "N/A")[:10]
    modified  = cve.get("lastModified", "N/A")[:10]

    score, severity, vector, version = extract_cvss(cve)
    description = extract_description(cve)
    col = CVSS_COLORS.get(severity.upper(), C.DIM)

    separator(cve_id)
    print(f"  {C.BOLD}Score{C.RESET}    : {col}{C.BOLD}{score} — {severity}{C.RESET}  {C.DIM}({version}){C.RESET}")
    print(f"  {C.BOLD}Vector{C.RESET}   : {C.DIM}{vector}{C.RESET}")
    print(f"  {C.BOLD}Publicado{C.RESET}: {published}   {C.BOLD}Atualizado{C.RESET}: {modified}")

    cwes = extract_weaknesses(cve)
    if cwes:
        print(f"  {C.BOLD}CWEs{C.RESET}     : {C.YELLOW}{', '.join(cwes)}{C.RESET}")

    if verbose:
        print(f"\n  {C.CYAN}Descrição:{C.RESET}")
        # Quebra linha a cada 80 chars
        words = description.split()
        line, lines = "", []
        for w in words:
            if len(line) + len(w) + 1 > 78:
                lines.append(line)
                line = w
            else:
                line = f"{line} {w}".strip()
        if line:
            lines.append(line)
        for l in lines:
            print(f"    {l}")

        refs = extract_references(cve)
        if refs:
            print(f"\n  {C.CYAN}Referências:{C.RESET}")
            for r in refs:
                print(f"    {C.DIM}{r}{C.RESET}")

        print(f"\n  {C.CYAN}ExploitDB:{C.RESET}")
        print(f"    {C.DIM}{EXPLOITDB_SEARCH}{cve_id}{C.RESET}")

    return {
        "id": cve_id,
        "score": score,
        "severity": severity,
        "version": version,
        "vector": vector,
        "published": published,
        "modified": modified,
        "description": description,
        "cwes": cwes,
        "references": extract_references(cve),
        "exploitdb": f"{EXPLOITDB_SEARCH}{cve_id}"
    }

# ─────────────────────────────────────────────────────────
# COMANDOS
# ─────────────────────────────────────────────────────────
def cmd_search(args):
    """Pesquisa CVEs por software/versão"""
    keyword = args.keyword
    limit   = min(args.limit, 20)

    print(f"\n{C.CYAN}[*] A pesquisar CVEs para:{C.RESET} {C.BOLD}{keyword}{C.RESET}")
    print(f"{C.DIM}    Fonte: NVD NIST · Limite: {limit} resultados{C.RESET}\n")

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": limit,
        "startIndex": 0
    }

    if args.severity:
        params["cvssV3Severity"] = args.severity.upper()

    data = fetch_nvd(params)
    total = data.get("totalResults", 0)
    items = data.get("vulnerabilities", [])

    print(f"{C.GREEN}[+] Total encontrado: {total}  |  A mostrar: {len(items)}{C.RESET}")

    results = []
    for item in items:
        r = print_cve(item, verbose=not args.short)
        results.append(r)

    if args.output:
        save_report(results, args.output, keyword)

def cmd_detail(args):
    """Mostra detalhes de um CVE específico"""
    cve_id = args.cve_id.upper()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"

    print(f"\n{C.CYAN}[*] A obter detalhes:{C.RESET} {C.BOLD}{cve_id}{C.RESET}\n")

    data = fetch_nvd({"cveId": cve_id})
    items = data.get("vulnerabilities", [])

    if not items:
        print(f"{C.RED}[!] CVE não encontrado: {cve_id}{C.RESET}")
        sys.exit(1)

    results = [print_cve(items[0], verbose=True)]

    if args.output:
        save_report(results, args.output, cve_id)

def cmd_check(args):
    """Verifica se um software/versão está vulnerável"""
    software = args.software
    version  = args.version

    query = f"{software} {version}"
    print(f"\n{C.CYAN}[*] A verificar vulnerabilidades:{C.RESET} {C.BOLD}{software} {version}{C.RESET}\n")

    data = fetch_nvd({"keywordSearch": query, "resultsPerPage": 10})
    items = data.get("vulnerabilities", [])
    total = data.get("totalResults", 0)

    if total == 0:
        print(f"{C.GREEN}[✓] Nenhuma CVE encontrada para {software} {version}{C.RESET}")
        print(f"{C.DIM}    Isto não garante que seja seguro — pesquisa manualmente na NVD{C.RESET}")
        return

    # Conta severidades
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    results = []

    for item in items:
        cve = item.get("cve", {})
        score, severity, vector, version_str = extract_cvss(cve)
        sev_upper = severity.upper()
        if sev_upper in counts:
            counts[sev_upper] += 1
        results.append(print_cve(item, verbose=False))

    separator("RESUMO DE RISCO")
    print(f"\n  Software : {C.BOLD}{software} {version}{C.RESET}")
    print(f"  Total CVEs (NVD): {C.BOLD}{total}{C.RESET}\n")

    for sev, count in counts.items():
        col = CVSS_COLORS.get(sev, C.DIM)
        bar = "█" * count
        print(f"  {col}{sev:<10}{C.RESET}  {bar} {count}")

    if counts["CRITICAL"] > 0 or counts["HIGH"] > 0:
        print(f"\n  {C.RED}{C.BOLD}⚠ SISTEMA EM RISCO ELEVADO — Atualiza ou mitiga imediatamente{C.RESET}")
    elif counts["MEDIUM"] > 0:
        print(f"\n  {C.YELLOW}⚠ Risco moderado — Avalia as CVEs e aplica patches{C.RESET}")
    else:
        print(f"\n  {C.GREEN}✓ Risco baixo — Mantém monitorização{C.RESET}")

    if args.output:
        save_report(results, args.output, f"{software} {version}")

def cmd_exploit(args):
    """Sugere exploits para um CVE"""
    cve_id = args.cve_id.upper()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"

    print(f"\n{C.CYAN}[*] A pesquisar exploits para:{C.RESET} {C.BOLD}{cve_id}{C.RESET}\n")

    # Detalhes do CVE
    data = fetch_nvd({"cveId": cve_id})
    items = data.get("vulnerabilities", [])

    if not items:
        print(f"{C.RED}[!] CVE não encontrado{C.RESET}")
        sys.exit(1)

    cve = items[0].get("cve", {})
    score, severity, vector, version_str = extract_cvss(cve)
    description = extract_description(cve)
    col = CVSS_COLORS.get(severity.upper(), C.DIM)

    separator("INFORMAÇÃO DO CVE")
    print(f"  ID       : {C.BOLD}{cve_id}{C.RESET}")
    print(f"  Score    : {col}{C.BOLD}{score} — {severity}{C.RESET}")
    print(f"  Descrição: {description[:120]}...")

    separator("RECURSOS DE EXPLOIT")

    resources = [
        ("ExploitDB",     f"https://www.exploit-db.com/search?cve={cve_id}"),
        ("Metasploit",    f"https://www.rapid7.com/db/?q={cve_id}&type=metasploit"),
        ("GitHub PoCs",   f"https://github.com/search?q={cve_id}&type=repositories"),
        ("Vulhub",        f"https://vulhub.org/#/environments/{cve_id}"),
        ("NVD Detail",    f"https://nvd.nist.gov/vuln/detail/{cve_id}"),
        ("MITRE",         f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"),
        ("PacketStorm",   f"https://packetstormsecurity.com/search/?q={cve_id}"),
    ]

    for name, url in resources:
        print(f"  {C.YELLOW}{name:<15}{C.RESET} → {C.DIM}{url}{C.RESET}")

    separator("DICAS DE EXPLORAÇÃO")
    cwes = extract_weaknesses(cve)
    if cwes:
        print(f"\n  Fraquezas: {C.YELLOW}{', '.join(cwes)}{C.RESET}")

    print(f"\n  {C.CYAN}Passos sugeridos:{C.RESET}")
    print(f"  1. Pesquisa o CVE no ExploitDB e Rapid7")
    print(f"  2. Procura módulo Metasploit: {C.DIM}search {cve_id}{C.RESET}")
    print(f"  3. Verifica PoCs no GitHub")
    print(f"  4. Testa em ambiente isolado (ex: Shadow Lab)")
    print(f"\n  {C.RED}⚠ Usa apenas em sistemas com autorização expressa{C.RESET}")

# ─────────────────────────────────────────────────────────
# RELATÓRIOS
# ─────────────────────────────────────────────────────────
def save_report(results, output_path, query):
    ext = os.path.splitext(output_path)[1].lower()

    if ext == ".json":
        save_json(results, output_path, query)
    elif ext == ".html":
        save_html(results, output_path, query)
    else:
        # Default JSON
        if not output_path.endswith(".json"):
            output_path += ".json"
        save_json(results, output_path, query)

def save_json(results, path, query):
    report = {
        "tool": "ShadowCVE",
        "author": "Mr. Joker · Shadow Suite",
        "query": query,
        "generated": datetime.datetime.now().isoformat(),
        "total": len(results),
        "results": results
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n{C.GREEN}[✓] Relatório JSON guardado:{C.RESET} {path}")

def save_html(results, path, query):
    rows = ""
    for r in results:
        sev = r.get("severity", "N/A").upper()
        colors = {
            "CRITICAL": "#ff4444",
            "HIGH":     "#ff8800",
            "MEDIUM":   "#ffcc00",
            "LOW":      "#44ff88",
        }
        col = colors.get(sev, "#888")
        refs_html = "".join(
            f'<a href="{ref}" target="_blank" style="display:block;color:#88ccff;font-size:11px">{ref[:60]}...</a>'
            for ref in r.get("references", [])[:3]
        )
        rows += f"""
        <tr>
            <td><b style="color:#00ff88">{r['id']}</b></td>
            <td style="color:{col};font-weight:bold">{r['score']} — {sev}</td>
            <td style="color:#aaa;font-size:12px">{r['vector']}</td>
            <td>{r['published']}</td>
            <td style="font-size:12px">{r['description'][:200]}...</td>
            <td style="font-size:11px">{refs_html}
                <a href="{r['exploitdb']}" target="_blank" style="color:#ff8800">ExploitDB ↗</a>
            </td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="pt">
<head>
<meta charset="UTF-8">
<title>ShadowCVE Report — {query}</title>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ background:#0a0a0a; color:#e0e0e0; font-family:'Courier New',monospace; padding:20px; }}
  h1 {{ color:#00ff88; font-size:28px; margin-bottom:4px; }}
  .sub {{ color:#555; font-size:13px; margin-bottom:20px; }}
  .meta {{ color:#888; font-size:12px; margin-bottom:24px; }}
  table {{ width:100%; border-collapse:collapse; }}
  th {{ background:#111; color:#00ff88; padding:10px; text-align:left; border-bottom:1px solid #333; font-size:13px; }}
  td {{ padding:10px; border-bottom:1px solid #1a1a1a; vertical-align:top; font-size:13px; }}
  tr:hover {{ background:#111; }}
  .badge {{ display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:bold; }}
  footer {{ margin-top:30px; color:#333; font-size:11px; text-align:center; }}
</style>
</head>
<body>
<h1>⚡ ShadowCVE Report</h1>
<div class="sub">by Mr. Joker · Shadow Suite · github.com/mrjoker-web</div>
<div class="meta">
  Pesquisa: <b style="color:#fff">{query}</b> &nbsp;|&nbsp;
  Total: <b style="color:#00ff88">{len(results)}</b> CVEs &nbsp;|&nbsp;
  Gerado: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
</div>
<table>
  <thead>
    <tr>
      <th>CVE ID</th>
      <th>Score</th>
      <th>Vector</th>
      <th>Data</th>
      <th>Descrição</th>
      <th>Recursos</th>
    </tr>
  </thead>
  <tbody>
    {rows}
  </tbody>
</table>
<footer>ShadowCVE · Uso exclusivamente educacional e em ambientes autorizados · Shadow Suite</footer>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n{C.GREEN}[✓] Relatório HTML guardado:{C.RESET} {path}")

# ─────────────────────────────────────────────────────────
# HELP
# ─────────────────────────────────────────────────────────
def cmd_help():
    separator("SHADOWCVE — COMANDOS")
    cmds = [
        ("search <keyword>",        "Pesquisa CVEs por software ou keyword"),
        ("detail <CVE-ID>",         "Detalhes completos de um CVE específico"),
        ("check <software> <ver>",  "Verifica se uma versão está vulnerável"),
        ("exploit <CVE-ID>",        "Recursos de exploit para um CVE"),
    ]
    for cmd, desc in cmds:
        print(f"  {C.GREEN}python shadowcve.py {cmd:<30}{C.RESET} {desc}")

    separator("OPÇÕES GLOBAIS")
    opts = [
        ("-o, --output <file>",  "Guarda relatório (.json ou .html)"),
        ("-l, --limit <n>",      "Nº de resultados (default: 10, max: 20)"),
        ("-s, --severity <lvl>", "Filtra por severidade: CRITICAL/HIGH/MEDIUM/LOW"),
        ("--short",              "Listagem resumida (sem descrição completa)"),
    ]
    for opt, desc in opts:
        print(f"  {C.CYAN}{opt:<25}{C.RESET} {desc}")

    separator("EXEMPLOS")
    examples = [
        "python shadowcve.py search apache --severity CRITICAL -o report.html",
        "python shadowcve.py detail CVE-2021-44228",
        "python shadowcve.py check nginx 1.18.0 -o nginx-report.json",
        "python shadowcve.py exploit CVE-2017-0144",
        "python shadowcve.py search openssh --limit 5 --short",
    ]
    for ex in examples:
        print(f"  {C.DIM}{ex}{C.RESET}")
    separator()

# ─────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────
def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        prog="shadowcve",
        description="ShadowCVE — CVE Intelligence Tool by Mr. Joker",
        add_help=False
    )
    subparsers = parser.add_subparsers(dest="command")

    # search
    p_search = subparsers.add_parser("search")
    p_search.add_argument("keyword")
    p_search.add_argument("-l", "--limit",    type=int, default=10)
    p_search.add_argument("-s", "--severity", type=str, default=None)
    p_search.add_argument("-o", "--output",   type=str, default=None)
    p_search.add_argument("--short",          action="store_true")

    # detail
    p_detail = subparsers.add_parser("detail")
    p_detail.add_argument("cve_id")
    p_detail.add_argument("-o", "--output", type=str, default=None)

    # check
    p_check = subparsers.add_parser("check")
    p_check.add_argument("software")
    p_check.add_argument("version")
    p_check.add_argument("-o", "--output", type=str, default=None)

    # exploit
    p_exploit = subparsers.add_parser("exploit")
    p_exploit.add_argument("cve_id")

    # help
    subparsers.add_parser("help")

    args = parser.parse_args()

    if not args.command or args.command == "help":
        cmd_help()
    elif args.command == "search":
        cmd_search(args)
    elif args.command == "detail":
        cmd_detail(args)
    elif args.command == "check":
        cmd_check(args)
    elif args.command == "exploit":
        cmd_exploit(args)
    else:
        cmd_help()

if __name__ == "__main__":
    main()
