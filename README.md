# ⚡ ShadowCVE

```
 ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗ ██████╗██╗   ██╗███████╗
 ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔════╝██║   ██║██╔════╝
 ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║██║     ██║   ██║█████╗
 ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██║     ╚██╗ ██╔╝██╔══╝
 ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝╚██████╗ ╚████╔╝ ███████╗
 ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝  ╚═════╝  ╚═══╝  ╚══════╝
```

**CVE Intelligence Tool for Pentesters**
by Mr. Joker · [Shadow Suite](https://github.com/mrjoker-web) · Uso exclusivamente educacional

---

## 📌 O que é

ShadowCVE é uma ferramenta CLI de inteligência de vulnerabilidades que consulta a base de dados oficial da **NVD (NIST)** em tempo real.

Permite pesquisar CVEs, analisar detalhes técnicos, verificar se um sistema está vulnerável e encontrar recursos de exploração — tudo num único comando, com relatórios exportáveis em JSON ou HTML.

---

## ⚙️ Instalação

```bash
# Sem dependências externas — usa apenas a stdlib do Python 3
git clone https://github.com/mrjoker-web/ShadowCVE
cd ShadowCVE
python3 shadowcve.py help
```

**Requisitos:** Python 3.8+

---

## 🚀 Comandos

### `search` — Pesquisa CVEs por software/keyword

```bash
python3 shadowcve.py search apache
python3 shadowcve.py search openssh --severity CRITICAL --limit 5
python3 shadowcve.py search nginx -o report.html
```

| Opção | Descrição |
|-------|-----------|
| `--limit <n>` | Nº de resultados (default: 10, max: 20) |
| `--severity` | Filtra por: CRITICAL / HIGH / MEDIUM / LOW |
| `--short` | Listagem resumida |
| `-o <file>` | Exporta relatório (.json ou .html) |

---

### `detail` — Detalhes completos de um CVE

```bash
python3 shadowcve.py detail CVE-2021-44228
python3 shadowcve.py detail CVE-2017-0144 -o log4shell.html
```

Mostra: score CVSS, vetor de ataque, descrição completa, CWEs, referências e link direto para ExploitDB.

---

### `check` — Verifica se um software está vulnerável

```bash
python3 shadowcve.py check nginx 1.18.0
python3 shadowcve.py check apache 2.4.49 -o apache-risk.json
```

Analisa as CVEs encontradas e devolve um **resumo de risco** com contagem por severidade.

---

### `exploit` — Recursos de exploit para um CVE

```bash
python3 shadowcve.py exploit CVE-2021-44228
python3 shadowcve.py exploit CVE-2017-0144
```

Lista links diretos para:
- ExploitDB
- Metasploit (Rapid7)
- GitHub PoCs
- Vulhub
- PacketStorm
- MITRE & NVD

---

## 📊 Relatórios

### JSON
```bash
python3 shadowcve.py search apache -o report.json
```

### HTML
```bash
python3 shadowcve.py search apache -o report.html
```
Gera um relatório visual com tema dark, tabela interativa e links diretos para recursos de exploit.

---

## 💡 Exemplos reais

```bash
# Log4Shell
python3 shadowcve.py detail CVE-2021-44228

# EternalBlue
python3 shadowcve.py exploit CVE-2017-0144

# Verificar Apache 2.4.49 (Path Traversal)
python3 shadowcve.py check apache 2.4.49 -o apache.html

# Top CVEs críticos de OpenSSH
python3 shadowcve.py search openssh --severity CRITICAL -o ssh-report.html
```

---

## 🛡️ Shadow Suite

ShadowCVE faz parte da **Shadow Suite** — ecossistema open-source de ferramentas para pentesting ético:

| Tool | Descrição |
|------|-----------|
| ShadowScan | Scanner de portas e serviços |
| ShadowSub | Enumeração de subdomínios |
| ShadowProbe | Fingerprinting web |
| **ShadowCVE** | Inteligência de CVEs |
| Shadow Lab | Ambiente Docker de prática |

---

## ⚠️ Aviso Legal

Esta ferramenta é para uso exclusivamente educacional e em ambientes com autorização expressa.
O autor não se responsabiliza por uso indevido.

---

*by Mr. Joker · Shadow Suite*
