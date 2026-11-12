# 👽 0xAlienSec ⚠️ Yautja Recon 🛸

![Version](https://img.shields.io/badge/VERSION-1.1-green?style=for-the-badge) ![Platform](https://img.shields.io/badge/PLATFORM-LINUX-blue?style=for-the-badge) ![Security](https://img.shields.io/badge/Security-Pentesting-purple?style=for-the-badge) ![License](https://img.shields.io/badge/LICENSE-MIT-orange?style=for-the-badge) ![Author](https://img.shields.io/badge/AUTHOR-0XALIENSEC-red?style=for-the-badge) 

**Yautja Recon** es una herramienta de reconocimiento y enumeración en modo clase, diseñada para entusiastas de la ciberseguridad y Pentesters. Guía las fases iniciales de una auditoría paso a paso, desde la detección de TTL hasta la generación de reportes en Markdown, explicando en cada fase qué hace, por qué y qué observar. Prioriza que aprendas: automatiza lo seguro y te deja listos para copiar los pasos lentos o ruidosos.

---

## 🚀 Características Principales

* **Modo clase:** Cada fase explica qué hace, por qué y qué observar. Se desactiva con `-q`.
* **Detección de OS (TTL):** Deduce Linux o Windows por el TTL de la respuesta ICMP. Si el host no responde, recomienda `-Pn` y explica el motivo.
* **Escaneo por fases:**
    * **Discovery rápido:** Barrido SYN de los 65535 puertos (`-sS -p-`), con selector de velocidad (`-T3/-T4/--min-rate`).
    * **Fingerprinting:** Servicios y versiones sobre los puertos abiertos (`-sV -sC`), verboso (`-v`).
* **Exploits públicos:** Cruza las versiones con `searchsploit`. Lista, no ejecuta.
* **Droid Mode:** Genera un script auto-destruible (`droid.sh`) para el escaneo de vulnerabilidades (`--script vuln`), para correrlo aparte cuando tú decidas.
* **Enumeración web:** WhatWeb y revisión de `robots.txt` y archivos típicos de forma automática. El **fuzzing** (Gobuster) y **Nikto** no se ejecutan: te entrega el comando listo para copiar, con recomendación de recursivo y diccionario profundo. Así ves los puertos sin esperar al fuzzing.
* **Extras de recon:** SMB (`smb-os-discovery`, protocolos, firma), FTP anónimo y detección de vhost con sugerencia para `/etc/hosts`.
* **Reporte y evidencia:** Genera `notashacking_<nombre>.md` pre-rellenado y empaqueta la evidencia en `.tar.gz` con su `SHA-256`.
* **Objetivo en la barra de Kali:** Muestra el target actual en el panel (XFCE Generic Monitor). Se borra en cada reinicio.

---

## 🕹️ Flujo de Trabajo

1.  **Configuración:** Detecta tu IP (`tun0` o `eth0`) y crea una estructura de carpetas ordenada (`nmap`, `exploit`, `otros`).
2.  **Ping Check:** Comprueba conectividad. Si el host no responde, recomienda y aplica `-Pn`.
3.  **Discovery:** Barrido rápido de todos los puertos (`-p-`).
4.  **Fingerprinting:** Versiones y scripts por defecto sobre los puertos abiertos, más `searchsploit`.
5.  **Extras:** SMB, FTP anónimo y vhost según los puertos encontrados.
6.  **Web Enum:** WhatWeb y archivos sensibles automáticos. Fuzzing y Nikto quedan como comandos listos para copiar.
7.  **Reporting:** Genera `notashacking_<nombre>.md` y, si quieres, empaqueta la evidencia con su hash.

---

## ⚙️ Opciones

```bash
sudo ./yautja_recon.sh [opciones]
  -y   Sin pausas entre fases (modo continuo)
  -q   Sin explicaciones (solo comandos y resultados)
  -p   Modo plan: imprime los comandos de cada fase con su explicación, sin ejecutar nada
  -h   Ayuda
```

---

## 🛡️ Aviso Legal
* **Este script ha sido creado únicamente con fines educativos y de auditoría ética. El uso de esta herramienta contra objetivos sin autorización previa es ilegal. El autor no se hace responsable del mal uso de este software.**

---

## 🛠️ Instalación

```bash
chmod +x yautja_recon.sh
sudo ./yautja_recon.sh
```
