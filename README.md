# ⚠️ Yautja Recon 🛸

![Version](https://img.shields.io/badge/Version-1.0-purple?style=for-the-badge) 
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-Pentesting-red?style=for-the-badge)

**Yautja Recon** es una herramienta automatizada de reconocimiento y enumeración diseñada para entusiastas de la ciberseguridad y Pentesters, este script optimiza las fases iniciales de una auditoría, desde la detección de TTL hasta la generación de reportes detallados en Markdown.

---

## 🚀 Características Principales

* **Detección de OS (TTL):** Identifica automáticamente si el objetivo es Linux o Windows mediante el análisis de paquetes ICMP.
* **Escaneo Inteligente:**
    * **Fase SYN rápida:** Descubrimiento veloz de puertos abiertos.
    * **Fase Agresiva:** Fingerprinting de servicios y versiones (`-sV -sC`).
* **Droid Mode:** Genera un script "auto-destruible" (`droid.sh`) específico para escaneos de vulnerabilidades mediante Nmap Scripts.
* **Enumeración Web Integrada:** Soporte para WhatWeb y Gobuster con selección de diccionarios personalizados y manejo de extensiones.

---

## 🕹️ Flujo de Trabajo

1.  **Configuración:** El script detecta tu IP (interfaz `tun0` o `eth0`) y crea una estructura de directorios organizada.
2.  **Ping Check:** Comprueba conectividad y permite omitir el chequeo si el host bloquea ICMP.
3.  **Discovery:** Escaneo rápido de todos los puertos abiertos (`-p-`).
4.  **Fingerprinting:** Análisis profundo de servicios en los puertos encontrados.
5.  **Web Enum:** Fuzzing de directorios y análisis de tecnologías si se detectan servicios HTTP/HTTPS.
6.  **Reporting:** Generación automática del archivo `notashacking_<nombre>.md` para documentación inmediata.

---
## 🛡️ Aviso Legal
* **Este script ha sido creado únicamente con fines educativos y de auditoría ética. El uso de esta herramienta contra objetivos sin autorización previa es ilegal. El autor no se hace responsable del mal uso de este software.**
---
## 🛠️ Instalación

```bash
chmod +x yautja_recon.sh
sudo ./yautja_recon.sh


