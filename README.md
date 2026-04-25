<div align="center">

```
 ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗ ██████╗██╗   ██╗███████╗
 ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔════╝██║   ██║██╔════╝
 ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║██║     ██║   ██║█████╗
 ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██║     ╚██╗ ██╔╝██╔══╝
 ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝╚██████╗ ╚████╔╝ ███████╗
 ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝  ╚═════╝  ╚═══╝  ╚══════╝
```

### `// CVE Intelligence Tool — Shadow Suite`

**NVD API · CVSSv3 · ExploitDB · Metasploit · HTML/JSON Reports**

[![Python](https://img.shields.io/badge/Python-3.6+-3776AB?style=for-the-badge&logo=python&logoColor=white)](.)
[![No Dependencies](https://img.shields.io/badge/dependencies-none-52c98b?style=for-the-badge)](.)
[![NVD NIST](https://img.shields.io/badge/Source-NVD%20NIST-e05260?style=for-the-badge)](https://nvd.nist.gov)
[![License](https://img.shields.io/badge/license-MIT-f0c94d?style=for-the-badge)](.)
[![Shadow Suite](https://img.shields.io/badge/Shadow-Suite-e05260?style=for-the-badge)](https://github.com/mrjoker-web)

</div>

---

## `> about`

**ShadowCVE** é uma ferramenta de inteligência de vulnerabilidades que consulta a base de dados oficial **NVD (National Vulnerability Database) do NIST** em tempo real — sem dependências externas, directo no terminal.

Pesquisa CVEs, verifica versões vulneráveis, analisa scores CVSS e gera relatórios profissionais em JSON ou HTML — integrado no pipeline da **Shadow Suite**.

```bash
# Descobre CVEs críticos do Apache em segundos
python shadowcve.py search apache --severity CRITICAL -o report.html
```

---

## `> pipeline integration`

```
ShadowScanner deteta → Apache 2.4.49 na porta 80
          │
          ▼
ShadowCVE check apache 2.4.49
          │
          ▼
  CVE-2021-41773  →  Score: 9.8 CRITICAL  →  Path Traversal + RCE
  CVE-2021-42013  →  Score: 9.8 CRITICAL  →  RCE via mod_cgi
          │
          ▼
shadowcve exploit CVE-2021-41773
          │
          ▼
  ExploitDB · Metasploit · GitHub PoCs · Vulhub · PacketStorm
          │
          ▼
      Relatório HTML para o cliente
```

---

## `> features`

```
┌──────────────────────────────────────────────────────────────┐
│                        FUNCIONALIDADES                       │
├─────────────────────┬────────────────────────────────────────┤
│ 🔍 search           │ Pesquisa CVEs por keyword/software      │
│ 📋 detail           │ Detalhes completos de um CVE            │
│ ✅ check            │ Verifica se uma versão está vulnerável  │
│ 💣 exploit          │ Recursos de exploit para um CVE         │
│ 📊 CVSSv3           │ Score, severidade, vector de ataque     │
│ 🔗 CWE              │ Fraquezas associadas (CWE-XX)           │
│ 📄 JSON Report      │ Export estruturado para pipelines       │
│ 🌐 HTML Report      │ Relatório visual para clientes          │
│ 🔎 ExploitDB link   │ Link directo para exploits públicos     │
│ 🟥 Severity filter  │ Filtra por CRITICAL/HIGH/MEDIUM/LOW     │
└─────────────────────┴────────────────────────────────────────┘
```

**Fontes consultadas:**

| Fonte | URL | O que fornece |
|-------|-----|---------------|
| NVD NIST | nvd.nist.gov | CVEs, CVSS, CWEs, referências |
| ExploitDB | exploit-db.com | Exploits públicos |
| Rapid7 | rapid7.com/db | Módulos Metasploit |
| GitHub | github.com | PoCs públicos |
| Vulhub | vulhub.org | Ambientes Docker vulneráveis |
| PacketStorm | packetstormsecurity.com | Exploits e advisories |
| MITRE | cve.mitre.org | Registo oficial do CVE |

---

## `> requirements`

```bash
Python 3.6+   # zero dependências externas
              # só stdlib — urllib, json, argparse
```

---

## `> install`

```bash
git clone https://github.com/mrjoker-web/ShadowCVE.git
cd ShadowCVE
python shadowcve.py help
```

---

## `> usage`

```bash
python shadowcve.py <comando> [opções]
```

### Comandos

#### `search` — Pesquisar CVEs por software

```bash
# Pesquisa básica
python shadowcve.py search apache

# Só CVEs críticos
python shadowcve.py search nginx --severity CRITICAL

# 15 resultados em modo resumido
python shadowcve.py search openssh --limit 15 --short

# Guardar relatório HTML
python shadowcve.py search log4j --severity HIGH -o report.html

# Guardar relatório JSON
python shadowcve.py search mysql 5.7 -o mysql-cves.json
```

#### `detail` — Detalhes de um CVE específico

```bash
# CVE do Log4Shell
python shadowcve.py detail CVE-2021-44228

# EternalBlue
python shadowcve.py detail CVE-2017-0144

# Com export
python shadowcve.py detail CVE-2021-44228 -o log4shell.json
```

#### `check` — Verificar se uma versão está vulnerável

```bash
# Verifica Apache 2.4.49
python shadowcve.py check apache 2.4.49

# Verifica OpenSSH 6.6.1
python shadowcve.py check openssh 6.6.1

# Verifica MySQL 5.7.0 e exporta
python shadowcve.py check mysql 5.7.0 -o mysql-audit.html
```

#### `exploit` — Recursos de exploit para um CVE

```bash
# Recursos para o Log4Shell
python shadowcve.py exploit CVE-2021-44228

# EternalBlue
python shadowcve.py exploit CVE-2017-0144

# Heartbleed
python shadowcve.py exploit CVE-2014-0160
```

### Todas as opções

```
Comandos:
  search <keyword>         Pesquisar CVEs por software/keyword
  detail <CVE-ID>          Detalhes completos de um CVE
  check  <software> <ver>  Verificar se uma versão é vulnerável
  exploit <CVE-ID>         Recursos de exploit para um CVE
  help                     Mostrar ajuda

Opções globais:
  -o, --output <file>      Relatório em .json ou .html
  -l, --limit <n>          Nº de resultados (default: 10, max: 20)
  -s, --severity <lvl>     CRITICAL | HIGH | MEDIUM | LOW
  --short                  Listagem resumida (sem descrição)
```

---

## `> output example`

```
  ── CVE-2021-44228 ─────────────────────────────────────

  Score    : 10.0 — CRITICAL  (CVSSv3.1)
  Vector   : CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
  Publicado: 2021-12-10   Atualizado: 2023-02-06
  CWEs     : CWE-917, CWE-502

  Descrição:
    Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases)
    JNDI features used in configuration, log messages, and parameters do
    not protect against attacker controlled LDAP and other JNDI related
    endpoints. An attacker who can control log messages or log message
    parameters can execute arbitrary code loaded from LDAP servers...

  Referências:
    https://logging.apache.org/log4j/2.x/security.html
    https://www.cisa.gov/uscert/apache-log4j-vulnerability-guidance
    https://github.com/advisories/GHSA-jfh8-c2jp-hqk

  ExploitDB:
    https://www.exploit-db.com/search?cve=CVE-2021-44228

  ── RECURSOS DE EXPLOIT ────────────────────────────────

  ExploitDB     → https://www.exploit-db.com/search?cve=CVE-2021-44228
  Metasploit    → https://www.rapid7.com/db/?q=CVE-2021-44228
  GitHub PoCs   → https://github.com/search?q=CVE-2021-44228
  Vulhub        → https://vulhub.org/#/environments/CVE-2021-44228
  NVD Detail    → https://nvd.nist.gov/vuln/detail/CVE-2021-44228
  MITRE         → https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228
  PacketStorm   → https://packetstormsecurity.com/search/?q=CVE-2021-44228
```

---

## `> severity scale`

```
  Score 9.0 – 10.0  →  🔴 CRITICAL  — Exploração remota, sem autenticação
  Score 7.0 – 8.9   →  🟠 HIGH      — Alto impacto, exploração provável
  Score 4.0 – 6.9   →  🟡 MEDIUM    — Exploração condicionada
  Score 0.1 – 3.9   →  🟢 LOW       — Impacto limitado
```

---

## `> html report`

O relatório HTML gerado com `-o report.html` inclui:

- Tabela completa com todos os CVEs encontrados
- Score e severidade com código de cores
- Vector CVSS e data de publicação
- Descrição truncada de cada CVE
- Links directos para ExploitDB por CVE
- Tema dark com identidade visual Shadow Suite

```bash
# Gera relatório HTML profissional
python shadowcve.py search nginx --severity HIGH -o nginx-audit.html

# Abre no browser
open nginx-audit.html   # macOS
xdg-open nginx-audit.html  # Linux
```

---

## `> use cases`

**Durante um pentest com Shadow Suite:**

```bash
# 1. ShadowScanner detecta serviços e versões
python shadowscanner.py target.com --top-ports -o scan.json

# 2. ShadowCVE verifica cada versão encontrada
python shadowcve.py check openssh 6.6.1
python shadowcve.py check apache 2.4.49
python shadowcve.py check redis 6.0

# 3. Para cada CVE crítico, pesquisa recursos de exploit
python shadowcve.py exploit CVE-2021-41773

# 4. Gera relatório final para o cliente
python shadowcve.py search apache 2.4.49 --severity CRITICAL -o client-report.html
```

**CVEs históricos para estudo:**

```bash
# Log4Shell
python shadowcve.py detail CVE-2021-44228

# EternalBlue (WannaCry)
python shadowcve.py detail CVE-2017-0144

# Heartbleed
python shadowcve.py detail CVE-2014-0160

# ShellShock
python shadowcve.py detail CVE-2014-6271

# Dirty Cow
python shadowcve.py detail CVE-2016-5195
```

---

## `> roadmap`

```
✅ search  — pesquisa por keyword com filtro de severidade
✅ detail  — detalhes completos com CVSSv3 e CWEs
✅ check   — verificação de versão vs CVEs conhecidos
✅ exploit — recursos de exploit agregados (7 fontes)
✅ Export JSON estruturado
✅ Export HTML com tema Shadow Suite
✅ Zero dependências externas
🔄 Integração directa com output do ShadowScanner
🔄 Auto-check de versões detectadas no scan
🔄 CVE watchlist — alertas para novos CVEs
🔄 Score EPSS (probabilidade de exploração)
🔄 Output Markdown para relatórios
```

---

## `> shadow suite`

| Tool | Descrição | Repo |
|------|-----------|------|
| 🌐 ShadowSub | Subdomain finder | [mrjoker-web/ShadowSub](https://github.com/mrjoker-web/ShadowSub) |
| ⚡ ShadowProbe | HTTP/HTTPS probe | [mrjoker-web/ShadowProbe](https://github.com/mrjoker-web/ShadowProbe) |
| 🔍 ShadowScan | Recon tool | [mrjoker-web/ShadowScan-Tool](https://github.com/mrjoker-web/ShadowScan-Tool) |
| 🛡️ ShadowScanner | Network scanner | [mrjoker-web/ShadowScanner](https://github.com/mrjoker-web/ShadowScanner) |
| 📱 ShadowDroid | Android ADB audit | [mrjoker-web/ShadowDroid-](https://github.com/mrjoker-web/ShadowDroid-) |
| ⚙️ ShadowSetup | Terminal setup | [mrjoker-web/ShadowSetup](https://github.com/mrjoker-web/ShadowSetup) |
| 🖥️ Shadow CLI | Full recon framework | [mrjoker-web/ShadowCLI](https://github.com/mrjoker-web/ShadowCLI) |
| 🧪 Shadow Lab | Practice environment | [mrjoker-web/ShadowLab](https://github.com/mrjoker-web/ShadowLab) |
| 🔎 ShadowCVE | CVE Intelligence | **este repo** |

---

## `> disclaimer`

```
⚠  AVISO LEGAL

Esta ferramenta consulta bases de dados públicas (NVD NIST).
Uso exclusivo para:
  • Auditorias profissionais em sistemas autorizados
  • Investigação de segurança e fins educacionais
  • Estudo e prática em ambientes isolados (Shadow Lab)

O autor não se responsabiliza por qualquer uso indevido.
```

---

## `> author`

<div align="center">

Feito por **[Mr Joker](https://github.com/mrjoker-web)** — Aspiring Pentester & Python Tools Developer · Lisboa, PT

[![GitHub](https://img.shields.io/badge/GitHub-mrjoker--web-181717?style=for-the-badge&logo=github)](https://github.com/mrjoker-web)
[![Telegram](https://img.shields.io/badge/Telegram-mr__joker78-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/mr_joker78)
[![Twitter/X](https://img.shields.io/badge/X-mrjoker3790-000000?style=for-the-badge&logo=x&logoColor=white)](https://x.com/mrjoker3790)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Mr%20Joker-0e76a8?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/mr-joker-951ab2357)

*Se achares útil, deixa uma ⭐ — ajuda a Shadow Suite a crescer!*

</div>
