# ⛓️ Chain-Tools

> **Automated Bug Bounty Recon Suite** · Multi-module · Python3 · Report-ready

[![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=flat-square&logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-557C94?style=flat-square&logo=kalilinux)](https://kali.org)
[![Type](https://img.shields.io/badge/Type-Bug%20Bounty%20Recon-FF6B35?style=flat-square)]()
[![Root](https://img.shields.io/badge/SYN%20Scan-requires%20sudo-red?style=flat-square)]()

---

## 📁 Estructura

```
chain/
├── main.py              # Orquestador principal
├── bugbounty_recon.py   # Script de reconocimiento
├── bug.py               # Módulo auxiliar
├── readme.md
└── README.md
```

---

## ⚙️ Instalación

```bash
# Dependencias Python
pip3 install python-nmap python-whois dnspython requests

# Permisos de ejecución
chmod +x bugbounty_recon.py
```

> 💡 El script auto-instala paquetes faltantes en el primer run.

---

## 🚀 Uso

### Scan básico
```bash
sudo python3 bugbounty_recon.py -t target.com
```

### Scan rápido (top ports, T5)
```bash
sudo python3 bugbounty_recon.py -t target.com --fast
```

### Scan completo (65535 puertos)
```bash
sudo python3 bugbounty_recon.py -t target.com -p 1-65535 --threads 100
```

### Saltar módulos específicos
```bash
sudo python3 bugbounty_recon.py -t target.com --skip-nmap --skip-reconng
```

### Con output personalizado
```bash
python3 bugbounty_recon.py --target example.com --output report.txt
```

---

## 🏳️ Flags disponibles

| Flag | Default | Descripción |
|---|---|---|
| `-t`, `--target` | **Requerido** | Dominio objetivo (e.g., `example.com`) |
| `-o`, `--output` | `_recon.txt` | Nombre del archivo de reporte |
| `-p`, `--ports` | `1-10000` | Rango de puertos para Nmap |
| `--speed` | `4` | Timing de Nmap (T1–T5) |
| `--threads` | `50` | Hilos para bruteforce de subdominios |
| `--fast` | `off` | Scan rápido: top ports, T5 speed |
| `--skip-whois` | `off` | Omitir WHOIS lookup |
| `--skip-nmap` | `off` | Omitir Nmap scan |
| `--skip-reconng` | `off` | Omitir Recon-ng / OSINT |
| `--skip-dns` | `off` | Omitir enumeración DNS |
| `--skip-http` | `off` | Omitir análisis de headers HTTP |
| `--skip-subs` | `off` | Omitir enumeración de subdominios |
| `-v`, `--verbose` | `off` | Output verboso |

---

## 📊 Output de ejemplo

```
BUG BOUNTY RECON REPORT
Target:   example.com
Start:    2024-03-01 10:12:03 UTC
End:      2024-03-01 10:14:12 UTC
Duration: 0:02:09

========================================
WHOIS
Command: whois example.com
Exit Code: 0
[STDOUT] ...
```

---

## 🔍 Review de resultados

```bash
# Ver reporte completo
cat target_com_recon.txt

# Buscar vulnerabilidades
grep -i "vuln|critical|high" target_com_recon.txt

# Extraer subdominios
grep -A 1000 "SUBDOMAINS" target_com_recon.txt | head -100
```

---

## 💡 Pro Tips — Bug Bounty

- **`--fast` primero**, luego `--all` en targets interesantes. Tiempo = dinero en bug bounties.
- **Chain tools**: alimenta subdominios a `httpx`, `nuclei` y `ffuf` para testing profundo.
- **Wayback URLs**: el script marca URLs sensibles de Wayback Machine — goldmines para configs expuestas.
- **Security Headers**: CORS misconfigs, CSP ausente y HSTS faltante son quick wins para reportes.
- **Subdomain Takeover**: revisa subdominios que resuelven a NXDOMAIN o apuntan a cloud resources sin reclamar.
- **Root requerido**: SYN scan (`-sS`) y OS detection (`-O`) requieren `sudo`. Sin root, Nmap usa TCP connect scan.

---

## ⚠️ Legal

Solo para uso en sistemas con **permiso explícito por escrito**. El uso no autorizado viola leyes de ciberseguridad en la mayoría de jurisdicciones.
