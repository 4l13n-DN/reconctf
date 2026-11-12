#!/usr/bin/env bash
#
#   TTL & Web Enum Scanner :: by 0xAlienSec
#
set -euo pipefail

# --- [0] Colores & globals ---
C_RST="\e[0m"
C_RED="\e[31m"
C_GRN="\e[32m"
C_YEL="\e[33m"
C_BLU="\e[34m"
C_CYN="\e[36m"
C_PUR="\e[35m"
C_BOLD="\e[1m"

TARGET_IP=""
ATTACKER_IP=""          # Tu IP (tun0 o eth0)
MACHINE_NAME=""
MACHINE_DIR=""
OUTPUT_DIR=""           # MACHINE_DIR/nmap
OPEN_PORTS_CSV=""       # Puertos abiertos detectados (fase rápida)
LOG_FILE=""             # logs_<maquina>.txt
PING_OMITIDO=0          # Variable de control para salto de ping
MODO_EXPLICAR=1         # 1 = muestra qué hace, por qué y qué observar en cada fase
MODO_AUTO=0             # 1 = sin pausas entre fases (-y)
MODO_IMPRIMIR=0         # 1 = solo imprime el plan de comandos, no ejecuta (-p)
TERMINOS_USADOS=()      # Glosario de la sesión
VHOST_DOMINIO=""        # Dominio detectado por redirección y resuelto en /etc/hosts
VEL=()                  # Opciones de velocidad elegidas para el escaneo en curso
T_INICIO=$(date +%s)

# Usuario original que lanzó sudo
ORIG_USER="${SUDO_USER:-${USER:-root}}"

trap 'echo -e "\n\n${C_YEL}[!] Abortado por el usuario.${C_RST}"; log_info "Proceso abortado por el usuario (Ctrl+C)."; [[ -n "${MACHINE_DIR}" && -d "${MACHINE_DIR}" ]] && chown -R "${ORIG_USER}:${ORIG_USER}" "${MACHINE_DIR}" 2>/dev/null; exit 1' INT

# --- [1] Helpers de Logging y Auditoría ---

log_info() {
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    [[ -n "${LOG_FILE}" ]] && echo "[${timestamp}] [INFO] $1" >> "${LOG_FILE}"
    return 0
}

log_cmd() {
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    [[ -n "${LOG_FILE}" ]] && echo "[${timestamp}] [CMD] EJECUTADO: $1" >> "${LOG_FILE}"
    return 0
}

log_data() {
    [[ -n "${LOG_FILE}" ]] && echo "$1" >> "${LOG_FILE}"
    return 0
}

imprimir_comando() {
    local cmd="$1"
    echo -e "${C_PUR}  [>] COMANDO EJECUTADO:${C_RST}"
    echo -e "      ${C_CYN}${cmd}${C_RST}"
    echo
    log_cmd "${cmd}"
}

ask_yes_no() {
    local prompt="$1"
    local ans
    echo -en "${C_YEL}[?] ${prompt} [s/N]: ${C_RST}"
    read -r ans
    [[ "${ans,,}" =~ ^(s|si|y|yes|1)$ ]]
}

# --- [1.0] Modo clase: explicaciones, pausas y tiempos ---
explicar() {
    # Uso: explicar "Título" "Qué hace" "Por qué" "Qué observar"
    [[ "${MODO_EXPLICAR}" -eq 1 ]] || return 0
    echo -e "${C_CYN}  ┌─ ${C_BOLD}$1${C_RST}"
    echo -e "${C_CYN}  │ ${C_RST}${C_BOLD}Qué hace:${C_RST}     $2"
    echo -e "${C_CYN}  │ ${C_RST}${C_BOLD}Por qué:${C_RST}      $3"
    echo -e "${C_CYN}  │ ${C_RST}${C_BOLD}Qué observar:${C_RST} $4"
    echo -e "${C_CYN}  └──────────────────────────────────────────────${C_RST}"
    echo
    log_info "EXPLICACIÓN [$1] $2 | $3 | $4"
}

pausa() {
    [[ "${MODO_AUTO}" -eq 1 ]] && return 0
    echo -en "${C_YEL}  [ Enter para continuar ]${C_RST}"
    read -r _ || true
    echo
}

tiempo_fase() {
    # Uso: tiempo_fase <segundos_inicio> "Nombre"
    local dur=$(( $(date +%s) - $1 ))
    echo -e "${C_PUR}  [⏱] $2: ${dur} s${C_RST}"
    log_info "Duración $2: ${dur} s"
}

usar_termino() {
    local t
    for t in "$@"; do
        [[ " ${TERMINOS_USADOS[*]:-} " == *" ${t} "* ]] || TERMINOS_USADOS+=("${t}")
    done
    return 0
}

definir_termino() {
    case "$1" in
        ROCKYOU)  echo "rockyou.txt: diccionario con millones de contraseñas reales filtradas. Que tu clave esté ahí significa que ya no es secreta." ;;
        NIKTO)    echo "Nikto: escáner de servidores web que busca archivos, versiones y configuraciones inseguras conocidas. Ruidoso: solo con permiso." ;;
        TIMING)   echo "Velocidad de nmap: -T0 a -T5 es la plantilla de tiempos. --min-rate fija un mínimo de paquetes por segundo. Más velocidad, más riesgo de perder resultados." ;;
        TTL)      echo "TTL (time to live): número que baja en cada salto de red. Su valor inicial sugiere el sistema operativo." ;;
        ICMP)     echo "ICMP: protocolo del ping. Muchos firewalls lo bloquean, y eso no significa que el equipo esté apagado." ;;
        SYN)      echo "SYN scan (-sS): escaneo medio abierto. Manda SYN y no completa el saludo TCP de tres vías." ;;
        PUERTO)   echo "Puerto: número que identifica un servicio en un equipo. Abierto significa que algo escucha." ;;
        NSE)      echo "NSE (Nmap Scripting Engine): scripts de nmap. -sC corre los de la categoría default." ;;
        VERSION)  echo "Fingerprinting (-sV): identificar servicio y versión exacta. De la versión salen las fallas públicas." ;;
        CVE)      echo "CVE: identificador único de una vulnerabilidad pública. CVSS mide su gravedad de 0 a 10." ;;
        EXPLOITDB) echo "Exploit-DB / searchsploit: base de exploits públicos. Listar no es ejecutar: se lee y se valida." ;;
        VHOST)    echo "Virtual host: un servidor web que responde distinto según el nombre de dominio pedido. Por eso se agrega a /etc/hosts." ;;
        FUZZING)  echo "Fuzzing de rutas: probar muchas palabras como rutas web para encontrar páginas no enlazadas." ;;
        HTTP)     echo "Códigos HTTP: 200 existe, 301/302 redirige, 401/403 existe pero protegido, 404 no existe." ;;
        SMB)      echo "SMB: protocolo de Windows para compartir archivos. SMBv1 es antiguo e inseguro." ;;
        FTP)      echo "FTP anónimo: acceso con usuario anonymous sin contraseña. Si está abierto, cualquiera lee los archivos." ;;
        HASH)     echo "SHA-256: huella del archivo. Si alguien lo modifica, la huella cambia. Prueba la integridad de la evidencia." ;;
        *)        echo "$1" ;;
    esac
}

uso() {
    cat <<USO
Yautja Recon v1.1 · modo clase · 0xAlienSec
Uso: sudo ./yautja_recon.sh [opciones]
  -y   Sin pausas entre fases (modo continuo)
  -q   Sin explicaciones (solo comandos y resultados)
  -p   Modo plan: imprime los comandos de cada fase con su explicación, sin ejecutar nada
  -h   Esta ayuda
Solo para laboratorios y CTF autorizados.
USO
}

# --- [1.05] Selector de velocidad de nmap ---
elegir_velocidad() {
    # Uso: elegir_velocidad "Nombre de la fase" <opcion_por_defecto 1-5>
    # Deja el resultado en el arreglo global VEL
    local fase="$1" def="$2" op t mr
    usar_termino TIMING
    echo -e "${C_YEL}[?] Velocidad para ${fase}:${C_RST}"
    echo    "    1) -T3                    Normal. Lo más confiable, más lento."
    echo    "    2) -T4                    Rápido. Bueno para laboratorio y CTF."
    echo    "    3) -T4 --min-rate 1000    Rápido con piso de paquetes. Buen equilibrio en VPN."
    echo    "    4) -T4 --min-rate 3000    Muy rápido. Riesgo de perder puertos."
    echo    "    5) Personalizado          Elegir -T0 a -T5 y, si quieres, un --min-rate."
    if [[ "${MODO_EXPLICAR}" -eq 1 ]]; then
        echo -e "${C_CYN}    -T es la plantilla de tiempos: -T0 muy lento y sigiloso, -T5 agresivo.${C_RST}"
        echo -e "${C_CYN}    --min-rate obliga a nmap a enviar al menos N paquetes por segundo.${C_RST}"
        echo -e "${C_RED}    Ojo: con --min-rate alto, la VPN o el objetivo pueden perder paquetes.${C_RST}"
        echo -e "${C_RED}    Un paquete perdido es un puerto que no aparece, o un script que no termina.${C_RST}"
        echo -e "${C_CYN}    Si algo no cuadra, repite con menos velocidad.${C_RST}"
    fi
    echo -en "${C_YEL}>> Opción [${def}]: ${C_RST}"
    read -r op || true
    op="${op:-$def}"
    case "${op}" in
        1) VEL=(-T3) ;;
        2) VEL=(-T4) ;;
        3) VEL=(-T4 --min-rate 1000) ;;
        4) VEL=(-T4 --min-rate 3000) ;;
        5)
            echo -en "${C_YEL}>> Plantilla -T (0 a 5) [4]: ${C_RST}"
            read -r t || true
            t="${t:-4}"
            [[ "${t}" =~ ^[0-5]$ ]] || { echo -e "${C_RED}[!] Inválido. Uso -T4.${C_RST}"; t=4; }
            VEL=("-T${t}")
            echo -en "${C_YEL}>> --min-rate (Enter = sin min-rate): ${C_RST}"
            read -r mr || true
            if [[ -n "${mr:-}" ]]; then
                if [[ "${mr}" =~ ^[0-9]+$ ]] && (( mr >= 1 && mr <= 10000 )); then
                    VEL+=(--min-rate "${mr}")
                else
                    echo -e "${C_RED}[!] min-rate inválido (1 a 10000). Se omite.${C_RST}"
                fi
            fi
            ;;
        *) echo -e "${C_RED}[!] Opción inválida. Uso la ${def}.${C_RST}"; elegir_velocidad_fija "${def}" ;;
    esac
    echo -e "${C_GRN}[+] Velocidad elegida: ${VEL[*]}${C_RST}"
    log_info "Velocidad ${fase}: ${VEL[*]}"
    echo
}

elegir_velocidad_fija() {
    case "$1" in
        1) VEL=(-T3) ;;
        2) VEL=(-T4) ;;
        3) VEL=(-T4 --min-rate 1000) ;;
        *) VEL=(-T4 --min-rate 3000) ;;
    esac
}

# --- [1.1] Detección de IP Atacante ---
detectar_mi_ip() {
    local ip=""
    if ip addr show tun0 >/dev/null 2>&1; then
        ip=$(ip -4 addr show tun0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || true)
        echo -e "${C_GRN}[VPN] Interfaz tun0 detectada.${C_RST}"
    elif ip addr show eth0 >/dev/null 2>&1; then
        ip=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || true)
        echo -e "${C_YEL}[LAN] Interfaz tun0 no existe. Usando eth0.${C_RST}"
    else
        ip=$(hostname -I | awk '{print $1}')
        echo -e "${C_YEL}[UNK] Usando hostname -I.${C_RST}"
    fi
    ATTACKER_IP="${ip:-desconocida}"
}

show_banner() {
    clear
    detectar_mi_ip
    echo -e "${C_BLU}=========================================================${C_RST}"
    echo -e "    ${C_BOLD}TTL & Web Enum Scanner${C_RST} :: ${C_YEL}v1.1 · modo clase${C_RST}"
    echo -e "                by 0xAlienSec"
    echo -e "${C_BLU}=========================================================${C_RST}"
    echo -e "    ${C_PUR}MI IP (Atacante):${C_RST} ${ATTACKER_IP}"
    echo -e "${C_BLU}=========================================================${C_RST}"
    echo
}

# --- [2] Validaciones ---
check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo -e "${C_RED}[!] Este script debe ejecutarse con sudo o como root.${C_RST}"
        exit 1
    fi
}

check_deps() {
    local deps=(ping nmap awk grep cut paste ip xsltproc curl sed)
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo -e "${C_RED}[-] Falta dependencia vital: $cmd${C_RST}"
            exit 1
        fi
    done
}

# --- [2.1] Configuración ---
configurar_maquina() {
    echo -e "${C_BLU}[*] CONFIGURACIÓN INICIAL${C_RST}"
    echo -en "${C_YEL}[?] Nombre de la máquina (sin espacios): ${C_RST}"
    read -r MACHINE_NAME || true

    if [[ ! "${MACHINE_NAME}" =~ ^[A-Za-z0-9._-]+$ || "${MACHINE_NAME}" == .* ]]; then
        echo -e "${C_RED}[!] Nombre inválido.${C_RST}"
        exit 1
    fi

    MACHINE_DIR="${MACHINE_NAME}"

    if [[ -d "${MACHINE_DIR}" ]]; then
        echo -e "${C_YEL}[i] Carpeta existente: ${MACHINE_DIR}.${C_RST}"
        if ask_yes_no "¿Deseas usar esta estructura existente?"; then
            echo -e "${C_GRN}[+] OK. Reutilizando estructura.${C_RST}"
        else
            echo -e "${C_RED}[!] Abortado.${C_RST}"
            exit 1
        fi
    else
        mkdir -p "${MACHINE_DIR}"/{nmap,exploit,otros}
        echo -e "${C_GRN}[+] Estructura creada.${C_RST}"
    fi

    OUTPUT_DIR="${MACHINE_DIR}/nmap"
    LOG_FILE="${MACHINE_DIR}/logs_${MACHINE_NAME}.txt"

    if [[ ! -f "${LOG_FILE}" ]]; then
        cat > "${LOG_FILE}" <<EOF
=====================================================
  BITÁCORA DE AUDITORÍA - 0xAlienSec Scanner
=====================================================
Target: ${MACHINE_NAME}
Fecha Inicio: $(date)
Usuario: ${ORIG_USER}
Kernel: $(uname -r)
=====================================================
EOF
    fi

    chown -R "${ORIG_USER}:${ORIG_USER}" "${MACHINE_DIR}"
    chmod -R 775 "${MACHINE_DIR}"
}

leer_ip_objetivo() {
    local previo="${MACHINE_DIR}/target.txt"
    TARGET_IP=""
    if [[ -s "${previo}" ]]; then
        local ip_prev
        ip_prev=$(head -n1 "${previo}")
        echo -e "${C_CYN}[i] Sesión anterior encontrada. Objetivo guardado: ${ip_prev}${C_RST}"
        echo -e "${C_YEL}[i] En muchas plataformas CTF la IP cambia cada vez que reinicias la máquina.${C_RST}"
        if ask_yes_no "¿Reanudar con esa misma IP?"; then
            TARGET_IP="${ip_prev}"
            log_info "Sesión reanudada con IP ${TARGET_IP}"
        fi
    fi
    if [[ -z "${TARGET_IP}" ]]; then
        echo -en "${C_YEL}[?] Ingresa la IP o dominio a analizar: ${C_RST}"
        read -r TARGET_IP || true
    fi

    if [[ ! "${TARGET_IP}" =~ ^[A-Za-z0-9.:-]+$ ]]; then
        echo -e "${C_RED}[!] IP o dominio inválido.${C_RST}"
        exit 1
    fi

    echo -e "${C_BLU}[*] Comprobando conectividad (ping)...${C_RST}"
    
    # --- Logica de Ping / -Pn ---
    if ping -c 1 -W 1 "${TARGET_IP}" >/dev/null 2>&1; then
        echo -e "${C_GRN}[+] Conectividad OK: responde a ping (ICMP).${C_RST}"
        echo -e "${C_CYN}    Por que: el host contesta ICMP, esta vivo y alcanzable. No hace falta forzar nada.${C_RST}"
        echo -e "${C_CYN}    Aun asi el escaneo usa -Pn, para no depender del ping y no perder puertos si el ICMP se filtra.${C_RST}"
        PING_OMITIDO=0
    else
        echo -e "${C_RED}[!] La maquina (${TARGET_IP}) NO responde a ping.${C_RST}"
        echo -e "${C_YEL}[i] No significa que este apagada: muchos firewalls bloquean ICMP.${C_RST}"
        echo -e "${C_GRN}[>] Recomendado en ESTE caso: escanear con -Pn (salta el ping y escanea igual).${C_RST}"
        echo -e "${C_CYN}    Yautja ya incluye -Pn en el escaneo, asi que puedes continuar.${C_RST}"
        if ask_yes_no "¿Continuar con -Pn (forzar el escaneo sin ping)?"; then
            echo -e "${C_GRN}[+] Entendido. Escaneo con -Pn, asumiendo el host vivo.${C_RST}"
            PING_OMITIDO=1
        else
            echo -e "${C_RED}[!] Abortado por el usuario. Revisa tu conexion/VPN.${C_RST}"
            exit 1
        fi
    fi
    # ----------------------------------------------------
    
    echo -e "${C_YEL}[TARGET]: ${TARGET_IP}${C_RST}"
    
    # --- [PERSISTENCIA] Crear target.txt ---
    local target_file="${MACHINE_DIR}/target.txt"
    echo "${TARGET_IP}" > "${target_file}"
    chown "${ORIG_USER}:${ORIG_USER}" "${target_file}"
    
    echo -e "${C_CYN}[i] IP guardada en: ${target_file}${C_RST}"
    echo -e "${C_CYN}[i] Tip: Ejecuta 'export IP=\$(<${target_file})' si necesitas la variable en tu terminal.${C_RST}"
    echo
    
    panel_target "${MACHINE_NAME} · ${TARGET_IP}"
    echo -e "${C_CYN}[i] Objetivo publicado en la barra superior (si tienes el Generic Monitor configurado).${C_RST}"
    log_info "Objetivo fijado: ${TARGET_IP}"
    log_info "IP Atacante: ${ATTACKER_IP}"
}

# --- [3] Nmap Fases ---
detectar_ttl_y_os() {
    local host="$1"
    echo -e "${C_BLU}[*] FASE 1: Detectando OS (TTL)${C_RST}"
    usar_termino TTL ICMP
    explicar "TTL (time to live, tiempo de vida)" \
        "Lee el TTL de la respuesta al ping." \
        "Cada sistema arranca con un TTL distinto: Linux 64, Windows 128, equipos de red 255. Cada router resta 1." \
        "Un 63 o 127 es normal en la VPN. Es una pista, no una prueba. Se confirma con nmap."
    
    # --- CORRECCION: Si se omitió el ping, no intentamos calcular TTL ---
    if [[ "${PING_OMITIDO}" -eq 1 ]]; then
        echo -e "${C_YEL}[i] Ping bloqueado/omitido. Imposible calcular TTL vía ICMP.${C_RST}"
        echo -e "${C_GRN}[+] Target: OS Indeterminado (ICMP Blocked)${C_RST}"
        log_info "Detección OS: Saltada (Ping omitido)."
        return
    fi
    # -------------------------------------------------------------------

    local ttl
    # Intentamos ping nuevamente solo para TTL
    ttl=$(ping -c1 -W1 "$host" 2>/dev/null | awk -F'ttl=' '/ttl=/{split($2,a," "); print a[1]; exit}' || true)

    local os="Desconocido / Sin respuesta ICMP"
    [[ -n "$ttl" ]] && {
        if    (( ttl <= 64 ));  then os="Linux/Unix (TTL: ${ttl})"
        elif (( ttl <= 128 )); then os="Windows (TTL: ${ttl})"
        else                        os="Otro (TTL: ${ttl})"
        fi
    }
    echo -e "${C_GRN}[+] Target: ${os}${C_RST}"
    log_info "Detección OS Finalizada. TTL: ${ttl} -> ${os}"
}

escaneo_nmap_rapido() {
    local host="$1"
    echo
    echo -e "${C_BLU}[*] FASE 2: Discovery Rápido (SYN)${C_RST}"
    usar_termino SYN PUERTO
    explicar "Escaneo SYN de todos los puertos" \
        "Prueba los 65535 puertos TCP con -sS (medio abierto) y -p-." \
        "Los servicios no siempre están en puertos comunes. -Pn salta el ping, --open muestra solo los abiertos. La velocidad la eliges tú." \
        "La lista de puertos abiertos. Cada uno es una puerta posible. Anótalos."
    local previo="${OUTPUT_DIR}/${host}_allports.nmap"
    if [[ -s "${previo}" ]] && grep -qE '^[0-9]+/tcp' "${previo}"; then
        local prev_csv
        prev_csv=$(grep -E '^[0-9]+/tcp' "${previo}" | cut -d'/' -f1 | paste -sd ',' - || true)
        echo -e "${C_CYN}[i] Ya hay un escaneo completo guardado para ${host}: ${prev_csv}${C_RST}"
        if ask_yes_no "¿Reutilizarlo y saltar el escaneo (ahorra varios minutos)?"; then
            OPEN_PORTS_CSV="${prev_csv}"
            log_info "Fase 2 reanudada desde ${previo}: ${OPEN_PORTS_CSV}"
            echo -e "${C_GRN}[+] Puertos recuperados:${C_RST} ${OPEN_PORTS_CSV}"
            echo
            pistas_puertos "${OPEN_PORTS_CSV}"
            return
        fi
    fi
    local t0; t0=$(date +%s)
    # Nota: Ya usas -Pn aqui, perfecto para cuando forzamos el escaneo
    elegir_velocidad "Fase 2 (todos los puertos)" 4
    local cmd="nmap -n -Pn -v ${VEL[*]} -sS --open -p- -oN ${OUTPUT_DIR}/${host}_allports.nmap ${host}"
    imprimir_comando "$cmd"

    nmap -n -Pn -v "${VEL[@]}" -sS --open -p- -oN "${OUTPUT_DIR}/${host}_allports.nmap" "${host}" || true
    tiempo_fase "${t0}" "Fase 2"
    local puertos_nl
    puertos_nl=$(grep -E '^[0-9]+/tcp' "${OUTPUT_DIR}/${host}_allports.nmap" 2>/dev/null | cut -d'/' -f1 || true)

    if [[ -z "${puertos_nl}" ]]; then
        echo -e "${C_RED}[-] 0 puertos abiertos.${C_RST}"
        log_info "Fase 2 terminada: 0 puertos abiertos."
        return
    fi

    OPEN_PORTS_CSV=$(echo "${puertos_nl}" | paste -sd ',' -)
    echo -e "${C_GRN}[+] Puertos descubiertos:${C_RST} ${OPEN_PORTS_CSV}"
    log_info "Puertos descubiertos: ${OPEN_PORTS_CSV}"
    echo
    pistas_puertos "${OPEN_PORTS_CSV}"
}

pistas_puertos() {
    # Qué suele ser cada puerto y qué revisar después (solo reconocimiento)
    [[ "${MODO_EXPLICAR}" -eq 1 ]] || return 0
    echo -e "${C_BLU}[*] Pistas para cada puerto (qué es y qué revisar después)${C_RST}"
    local p
    for p in ${1//,/ }; do
        case "$p" in
            21)   echo "  21    FTP    → ¿acepta login anónimo? Revisa versión y archivos visibles." ;;
            22)   echo "  22    SSH    → Anota la versión. Sirve si consigues usuarios y credenciales." ;;
            23)   echo "  23    Telnet → Protocolo sin cifrado. Hallazgo por sí solo." ;;
            25)   echo "  25    SMTP   → Puede revelar usuarios válidos." ;;
            53)   echo "  53    DNS    → ¿Permite transferencia de zona?" ;;
            80|8080|8000|8888|3333) echo "  $p    Web    → whatweb, robots.txt y fuzzing de rutas (ENUMWEB)." ;;
            443|8443) echo "  $p   HTTPS  → Igual que web, más el certificado: puede revelar nombres de dominio." ;;
            110|143) echo "  $p   Correo → Anota versión. Útil si consigues credenciales." ;;
            111|2049) echo "  $p   RPC/NFS → ¿Hay carpetas compartidas montables? (showmount -e)" ;;
            135)  echo "  135   RPC    → Típico de Windows. Confirma el sistema." ;;
            139|445) echo "  $p   SMB    → enum4linux, netexec y scripts smb-vuln-* de nmap. Revisa la versión de SMB." ;;
            1433) echo "  1433  MSSQL  → Base de datos Windows. Anota versión." ;;
            3306) echo "  3306  MySQL  → Base de datos. ¿Expuesta a la red sin necesidad?" ;;
            3389) echo "  3389  RDP    → Escritorio remoto de Windows. Sirve si consigues credenciales." ;;
            5985|5986) echo "  $p  WinRM  → Administración remota de Windows." ;;
            49[0-9][0-9][0-9]) echo "  $p RPC dinámico de Windows → normalmente no es el vector." ;;
            *)    echo "  $p    ?      → Desconocido: -sV te dirá qué es." ;;
        esac
    done
    echo
}

escaneo_nmap_agresivo() {
    local host="$1"
    local port_list="$2"
    local base_name="${host}_version_scan"
    local output_base="${OUTPUT_DIR}/${base_name}"
    
    rm -f "${output_base}".* 2>/dev/null

    echo
    echo -e "${C_BLU}[*] FASE 3: Fingerprinting de Servicios (-sV -sC)${C_RST}"
    usar_termino VERSION NSE
    explicar "Versiones y scripts por defecto" \
        "Pregunta a cada puerto abierto qué servicio y qué versión corre (-sV) y corre los scripts seguros por defecto (-sC)." \
        "Solo sobre los puertos abiertos: es mucho más rápido que hacerlo en los 65535. La versión exacta dice si hay fallas públicas." \
        "Nombre y versión de cada servicio, títulos web, nombre del equipo y datos de SMB. -oA guarda la evidencia en 3 formatos."
    local t0; t0=$(date +%s)
    elegir_velocidad "Fase 3 (versiones y scripts)" 2
    local cmd="nmap -n -Pn -sV -sC -vv ${VEL[*]} -p${port_list} -oA ${output_base} ${host}"
    imprimir_comando "$cmd"
    
    nmap -n -Pn -sV -sC -vv "${VEL[@]}" -p"${port_list}" -oA "${output_base}" "${host}" || true
    tiempo_fase "${t0}" "Fase 3"
    generar_html "${output_base}.xml" "${output_base}.html"
    buscar_exploits_publicos "${output_base}.xml"
    
    if [[ -f "${output_base}.nmap" ]]; then
        log_info "Fase 3 finalizada. Guardando detalle de puertos."
        log_data ""
        log_data "--- Detalle Puertos (Nmap Output) ---"
        awk '/^[0-9]+\/tcp/ {print $0}' "${output_base}.nmap" >> "${LOG_FILE}"
    fi
}

buscar_exploits_publicos() {
    # Lista exploits públicos conocidos para las versiones detectadas. No ejecuta nada.
    local xml="$1"
    [[ -f "${xml}" ]] || return 0
    command -v searchsploit >/dev/null 2>&1 || { log_info "searchsploit no instalado."; return 0; }
    echo
    echo -e "${C_BLU}[*] FASE 3B: Exploits públicos conocidos (searchsploit)${C_RST}"
    usar_termino CVE EXPLOITDB
    explicar "searchsploit sobre el escaneo" \
        "Cruza las versiones que encontró nmap con la base de Exploit-DB que trae Kali." \
        "Si una versión tiene fallas públicas, aparece aquí. Es análisis de vulnerabilidades: no ejecuta nada." \
        "Coincidencias con la versión exacta. Una coincidencia no confirma la falla: hay que leer y validar."
    local out="${OUTPUT_DIR}/searchsploit.txt"
    imprimir_comando "searchsploit --nmap ${xml}"
    searchsploit --nmap "${xml}" 2>/dev/null | tee "${out}" || true
    log_info "searchsploit guardado en ${out}"
}

generar_html() {
    local xml_in="$1"
    local html_out="$2"
    if [[ -f "${xml_in}" ]]; then
        xsltproc "${xml_in}" -o "${html_out}" 2>/dev/null
        echo -e "${C_GRN}[OK] HTML: ${html_out}${C_RST}"
    fi
}

# --- [3B] Generar droide MANUAL ---
generar_droide_vuln() {
    local host="$1"
    local port_list="$2"
    [[ -z "${port_list}" ]] && return

    local droid_path="${MACHINE_DIR}/droid.sh"
    echo -e "${C_CYN}[i] droid.sh corre --script vuln. Esos scripts necesitan respuestas completas: conviene ir más lento.${C_RST}"
    elegir_velocidad "droid.sh (scripts vuln)" 2
    local droid_vel="${VEL[*]}"

    # Generamos el script
    cat > "${droid_path}" <<EOF
#!/usr/bin/env bash
# Droide de Vulnerabilidades - AutoDestruct Edition
set -euo pipefail

if [[ "\${EUID}" -ne 0 ]]; then
    echo "Ejecuta con sudo."
    exit 1
fi

HOST="${host}"
PORT_LIST="${port_list}"
OUTPUT_DIR="nmap"
BASE_NAME="\${HOST}_vuln_scan"

echo "Ejecutando escaneo vuln sobre \${HOST}..."
VEL="${droid_vel}"
echo "Velocidad: \${VEL}"
# shellcheck disable=SC2086
nmap -n -Pn \${VEL} --script vuln --script-timeout 60s -vv -p"\${PORT_LIST}" -oA "\${OUTPUT_DIR}/\${BASE_NAME}" "\${HOST}"

if [[ -f "\${OUTPUT_DIR}/\${BASE_NAME}.xml" ]]; then
    xsltproc "\${OUTPUT_DIR}/\${BASE_NAME}.xml" -o "\${OUTPUT_DIR}/\${BASE_NAME}.html"
fi

echo "Auto-destruyendo este script..."
rm -- "\$0"
EOF

    chmod +x "${droid_path}"
    
    # --- RECUPERADO: Instrucción explícita de cómo ejecutarlo ---
    explicar "droid.sh (escaneo de vulnerabilidades aparte)" \
        "Deja listo un script con nmap --script vuln sobre los puertos encontrados." \
        "Se corre aparte porque es más lento y más ruidoso. Así decides cuándo lanzarlo." \
        "Las líneas VULNERABLE con su CVE. Es la evidencia de la sección 2 del informe."
    echo -e "${C_GRN}[+] Droide generado: ${droid_path}${C_RST}"
    echo -e "${C_YEL}[VULNS] Ejecutar manual: cd ${MACHINE_DIR} && sudo ./droid.sh${C_RST}"
    
    log_info "Droide generado en ${droid_path} (esperando ejecución manual)."
}

# --- [4] ENUMWEB ---
# Devuelve el esquema que responde (https primero, luego http). Vacío si ninguno.
detectar_esquema_web() {
    local host="$1"
    local port="$2"
    local code
    code=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 3 "https://${host}:${port}/" || true)
    if [[ "${code}" =~ ^[1-5][0-9][0-9]$ ]]; then echo "https"; return 0; fi
    code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 "http://${host}:${port}/" || true)
    if [[ "${code}" =~ ^[1-5][0-9][0-9]$ ]]; then echo "http"; return 0; fi
    echo ""
}

enum_web_port() {
    local host="$1"
    local port="$2"
    local web_dir="${MACHINE_DIR}/otros/enum_${host}_${port}"
    local scheme

    echo
    echo -e "${C_BLU}[*] FASE 4: ENUMWEB sobre ${host}:${port}${C_RST}"
    
    echo -en "${C_YEL}[?] Validando si el puerto ${port} es web (HTTPS o HTTP)... ${C_RST}"
    scheme=$(detectar_esquema_web "${host}" "${port}")
    if [[ -z "${scheme}" ]]; then
        echo -e "${C_RED}NO.${C_RST}"
        log_info "WEB: Puerto ${port} descartado (sin respuesta web)."
        return
    fi
    echo -e "${C_GRN}SÍ (${scheme}).${C_RST}"
    local base_url="${scheme}://${host}:${port}"
    detectar_vhost "${scheme}" "${host}" "${port}"
    if [[ -n "${VHOST_DOMINIO}" ]]; then
        base_url="${scheme}://${VHOST_DOMINIO}:${port}"
        echo -e "${C_CYN}[i] Desde aquí la enumeración usa el dominio: ${base_url}${C_RST}"
        echo -e "${C_CYN}    Por qué: el servidor muestra el sitio real solo cuando le pides ese nombre.${C_RST}"
        log_info "ENUMWEB usa el vhost ${base_url}"
    fi

    usar_termino FUZZING HTTP
    explicar "Enumeración web" \
        "whatweb identifica tecnologías. gobuster prueba rutas con un diccionario. Se revisan robots.txt y archivos típicos." \
        "Muchas páginas existen pero no están enlazadas. El servidor solo las muestra si las pides por su nombre." \
        "Códigos 200 (existe), 301/302 (redirige), 401/403 (existe pero protegido). Rutas tipo admin, dev, backup, login."
    mkdir -p "${web_dir}"
    log_data ""
    log_data "=== ENUMWEB ${base_url} ==="
    log_info "Iniciando análisis web en ${base_url}"

    # --- Whatweb ---
    echo "--- Whatweb ---"
    local cmd_whatweb="whatweb -v ${base_url}"
    
    if command -v whatweb >/dev/null 2>&1; then
        imprimir_comando "$cmd_whatweb"
        whatweb -v "${base_url}" | tee "${web_dir}/whatweb.txt" || echo -e "${C_RED}[!] Error whatweb${C_RST}"
    else
        log_info "Whatweb no instalado."
    fi


    # --- Archivos Sensibles ---
    echo "--- Archivos Sensibles ---"
    local SENSITIVE=("robots.txt" "sitemap.xml" "license.txt" "readme.html")
    for file in "${SENSITIVE[@]}"; do
        local url="${base_url}/${file}"
        local status
        status=$(curl -sk -o "${web_dir}/${file}" -w "%{http_code}" "${url}" || echo "ERR")
        if [[ "$status" == "200" ]]; then
            echo -e "${C_GRN}[+] Encontrado y guardado: ${url} -> ${web_dir}/${file}${C_RST}"
            if [[ "${file}" == "robots.txt" && -s "${web_dir}/${file}" ]]; then
                echo -e "${C_CYN}  Contenido de robots.txt:${C_RST}"
                sed 's/^/    /' "${web_dir}/${file}" | head -30 || true
            fi
            log_data "Sensible encontrado: ${url}"
        else
            rm -f "${web_dir}/${file}"
        fi
    done
    # --- Fuzzing web: comando listo (no se corre aqui, se copia) ---
    fuzzing_comando "${base_url}" "${web_dir}"
    nikto_web "${base_url}" "${web_dir}"
    echo -e "${C_GRN}[OK] Resultados en: ${web_dir}${C_RST}"
}

# --- [2.1b] Target en la barra superior de Kali (XFCE Generic Monitor) ---
PANEL_FILE="/tmp/yautja_target"     # /tmp se borra en cada reinicio

panel_target() {
    # Uso: panel_target "<texto>"   (vacío = sin objetivo)
    # /tmp tiene sticky bit y Kali activa fs.protected_regular: root no puede
    # sobrescribir un archivo de otro usuario ahí, pero sí borrarlo y crearlo de nuevo.
    rm -f "${PANEL_FILE}" 2>/dev/null || true
    { printf '%s\n' "$1" > "${PANEL_FILE}"; } 2>/dev/null || {
        log_info "No se pudo escribir ${PANEL_FILE} (barra superior). Se continúa."
        return 0
    }
    chown "${ORIG_USER}:${ORIG_USER}" "${PANEL_FILE}" 2>/dev/null || true
    chmod 644 "${PANEL_FILE}" 2>/dev/null || true
}

preparar_panel() {
    # Crea el script que lee el panel y explica cómo agregarlo una sola vez
    local home helper rc
    home=$(getent passwd "${ORIG_USER}" | cut -d: -f6)
    [[ -n "${home}" && -d "${home}" ]] || return 0
    helper="${home}/.local/bin/yautja-panel.sh"
    if [[ ! -x "${helper}" ]]; then
        mkdir -p "${home}/.local/bin"
        cat > "${helper}" <<'PANEL'
#!/bin/bash
# Muestra el objetivo actual de Yautja en la barra de Kali (Generic Monitor)
f=/tmp/yautja_target
if [ -s "$f" ]; then
    echo "<txt>  ◎ $(head -n1 "$f")  </txt>"
    echo "<tool>Objetivo actual de Yautja Recon</tool>"
else
    echo "<txt>  ◎ sin objetivo  </txt>"
fi
PANEL
        chmod 755 "${helper}"
        chown -R "${ORIG_USER}:${ORIG_USER}" "${home}/.local" 2>/dev/null || true
        log_info "Helper del panel creado en ${helper}"
    fi
    rc=$(grep -l "yautja-panel.sh" "${home}"/.config/xfce4/panel/genmon-*.rc 2>/dev/null | head -n1 || true)
    if [[ -z "${rc}" ]]; then
        echo -e "${C_CYN}[i] Para ver el objetivo en la barra superior de Kali (se configura una sola vez):${C_RST}"
        echo    "    1) sudo apt install xfce4-genmon-plugin   (si no lo tienes)"
        echo    "    2) Clic derecho en la barra → Panel → Agregar nuevos elementos → Generic Monitor"
        echo    "    3) Clic derecho en el nuevo elemento → Propiedades:"
        echo    "         Comando:   ${helper}"
        echo    "         Etiqueta:  desmarcar"
        echo    "         Período:   2 segundos"
        echo -e "${C_CYN}    Desde ahí la barra muestra el objetivo de cada ejecución. Al reiniciar Kali vuelve a 'sin objetivo'.${C_RST}"
        echo
    fi
}

# --- [2.2] Preparación del entorno: rockyou ---
revisar_rockyou() {
    local dir="/usr/share/wordlists" txt="/usr/share/wordlists/rockyou.txt" gz="/usr/share/wordlists/rockyou.txt.gz"
    echo -e "${C_BLU}[*] PREPARACIÓN: diccionario rockyou${C_RST}"
    usar_termino ROCKYOU
    explicar "rockyou.txt" \
        "Revisa si el diccionario rockyou está listo para usar en ${dir}." \
        "Es la lista de contraseñas más usada en CTF: millones de claves reales filtradas. Kali la trae comprimida y hay que descomprimirla una vez." \
        "Si dice LISTO, ya puedes usarla con john o hydra. Si está solo el .gz, se descomprime aquí."
    if [[ -s "${txt}" ]]; then
        echo -e "${C_GRN}[+] rockyou LISTO: ${txt} ($(du -h "${txt}" | cut -f1))${C_RST}"
        log_info "rockyou disponible en ${txt}"
    elif [[ -s "${gz}" ]]; then
        echo -e "${C_YEL}[i] Solo existe la versión comprimida: ${gz}${C_RST}"
        if ask_yes_no "¿Descomprimirla ahora (gzip -dk, conserva el .gz)?"; then
            imprimir_comando "gzip -dk ${gz}"
            gzip -dk "${gz}"
            echo -e "${C_GRN}[+] Listo: ${txt} ($(du -h "${txt}" | cut -f1))${C_RST}"
            log_info "rockyou descomprimido en ${txt}"
        fi
    else
        echo -e "${C_YEL}[i] No se encontró rockyou en ${dir}.${C_RST}"
        echo -e "${C_YEL}    En Kali se instala con: sudo apt install wordlists${C_RST}"
        log_info "rockyou no encontrado"
    fi
    echo
}

# --- [4C] Nikto opcional ---
nikto_web() {
    # No se ejecuta aquí: tarda mucho. Deja el comando listo para correrlo en otra terminal.
    local base_url="$1" web_dir="$2"
    echo
    echo -e "${C_BLU}[*] FASE 4C: Nikto (comando listo para correr aparte)${C_RST}"
    usar_termino NIKTO
    explicar "Nikto" \
        "Revisa el servidor web contra miles de pruebas conocidas: archivos peligrosos, versiones viejas, cabeceras faltantes y configuraciones inseguras." \
        "Complementa a gobuster: gobuster busca rutas, nikto busca problemas conocidos. Es lento y ruidoso, por eso no corre aquí: lo lanzas en otra terminal mientras sigues trabajando." \
        "Líneas que empiezan con +. Prioriza versiones desactualizadas, respaldos o configuración expuestos y métodos HTTP peligrosos. Valida antes de anotarlos."
    local out cmd pend
    out="$(realpath -m "${web_dir}")/nikto.txt"
    cmd="nikto -h ${base_url} -maxtime 10m -o ${out} -Format txt"
    pend="${MACHINE_DIR}/comandos_pendientes.txt"
    command -v nikto >/dev/null 2>&1 || echo -e "${C_YEL}[i] nikto no está instalado: sudo apt install nikto${C_RST}"
    echo -e "${C_GRN}[+] Comando listo (cópialo en otra terminal):${C_RST}"
    echo -e "      ${C_CYN}${cmd}${C_RST}"
    echo -e "${C_CYN}    -maxtime 10m limita el tiempo. Súbelo si quieres una revisión completa.${C_RST}"
    echo "# Nikto ${base_url} ($(date '+%F %H:%M'))" >> "${pend}"
    echo "${cmd}" >> "${pend}"
    echo -e "${C_GRN}[+] También quedó guardado en ${pend}${C_RST}"
    log_info "Nikto pendiente (no ejecutado): ${cmd}"
}

# --- [4B] Fuzzing web: comando listo para ejecutar a mano ---
fuzzing_comando() {
    local base_url="$1" web_dir="$2"
    echo
    echo -e "${C_BLU}[*] FASE 4B: Fuzzing web (comando listo, se corre a mano)${C_RST}"
    usar_termino FUZZING
    explicar "Fuerza de directorios (fuzzing)" \
        "Prueba miles de rutas de un diccionario contra la web para descubrir paginas y carpetas que no estan enlazadas." \
        "No se corre aqui a proposito: es el paso que mas tarda. Asi ves los puertos y el resto del recon sin esperar. Copia el comando y lanzalo en otra terminal mientras sigues." \
        "Codigos 200 (existe), 301/302 (carpeta), 401/403 (protegido). Prioriza admin, login, backup, dev, config. Si una carpeta sale interesante, haz un segundo nivel dentro de ella (a mano, max 2 niveles)."
    local out pend cmd rec
    mkdir -p "${web_dir}"
    out="$(realpath -m "${web_dir}")/gobuster.txt"
    pend="${MACHINE_DIR}/comandos_pendientes.txt"
    command -v gobuster >/dev/null 2>&1 || echo -e "${C_YEL}[i] gobuster no esta instalado: sudo apt install gobuster${C_RST}"
    cmd="gobuster dir -u ${base_url} -w /usr/share/wordlists/dirb/common.txt -x php,txt,html -t 150 -k --no-error -o ${out}"
    rec="gobuster dir -u ${base_url}/CARPETA/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,html,bak -t 150 -k --no-error -o $(realpath -m "${web_dir}")/gobuster_CARPETA.txt"
    echo -e "${C_GRN}[+] Comando de fuzzing (copialo en otra terminal):${C_RST}"
    echo -e "      ${C_CYN}${cmd}${C_RST}"
    echo -e "${C_CYN}    Muestra en vivo cada ruta que encuentra. Si quieres ver cada intento, agrega -v (ruidoso).${C_RST}"
    echo -e "${C_CYN}    Si el rapido no da nada, usa un diccionario mas profundo:${C_RST}"
    echo -e "      ${C_CYN}/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt${C_RST}"
    echo -e "${C_GRN}[+] Si una carpeta sale interesante, segundo nivel (reemplaza CARPETA):${C_RST}"
    echo -e "      ${C_CYN}${rec}${C_RST}"
    {
        echo "# Fuzzing web ${base_url} ($(date '+%F %H:%M'))"
        echo "${cmd}"
        echo "# Segundo nivel si hay carpeta interesante (reemplaza CARPETA):"
        echo "${rec}"
    } >> "${pend}"
    echo -e "${C_GRN}[+] Guardado en ${pend} y quedara en el reporte .md${C_RST}"
    log_info "Fuzzing pendiente (no ejecutado): ${cmd}"
}

# --- [5] Funciones extra de reconocimiento ---

detectar_vhost() {
    # Si la web redirige a un dominio, sugiere agregarlo a /etc/hosts
    local scheme="$1" host="$2" port="$3"
    local destino dominio
    VHOST_DOMINIO=""
    destino=$(curl -sk -o /dev/null -w "%{redirect_url}" --connect-timeout 5 "${scheme}://${host}:${port}/" || true)
    [[ -z "${destino}" ]] && return 0
    dominio=$(echo "${destino}" | sed -E 's#^[a-zA-Z]+://##; s#[:/].*$##')
    if [[ -z "${dominio}" || "${dominio}" =~ ^[0-9.]+$ ]]; then
        return 0
    fi
    usar_termino VHOST
    echo -e "${C_YEL}[!] La web redirige a: ${destino}${C_RST}"
    explicar "Virtual host (vhost)" \
        "El servidor responde con un nombre de dominio en vez de la IP." \
        "Tu Kali no sabe a qué IP apunta ese nombre: sin /etc/hosts la web no carga o muestra otra página." \
        "Después de agregarlo, abre http://${dominio} en el navegador y vuelve a enumerar con ese nombre."
    log_info "VHOST detectado: ${dominio} (redirección desde ${scheme}://${host}:${port})"
    if grep -qE "[[:space:]]${dominio}([[:space:]]|$)" /etc/hosts; then
        echo -e "${C_GRN}[+] ${dominio} ya está en /etc/hosts.${C_RST}"
        VHOST_DOMINIO="${dominio}"
        return 0
    fi
    echo -e "${C_CYN}  Línea sugerida: ${host}    ${dominio}${C_RST}"
    if ask_yes_no "¿Agregarla a /etc/hosts?"; then
        imprimir_comando "echo '${host}    ${dominio}' >> /etc/hosts"
        echo "${host}    ${dominio}" >> /etc/hosts
        echo -e "${C_GRN}[+] Agregado. Desde ahora puedes usar ${dominio}.${C_RST}"
        VHOST_DOMINIO="${dominio}"
        log_info "Agregado a /etc/hosts: ${host} ${dominio}"
    fi
}

puerto_abierto() {
    # Uso: puerto_abierto <puerto>  → 0 si está en la lista de abiertos
    [[ ",${OPEN_PORTS_CSV}," == *",$1,"* ]]
}

enum_smb_basico() {
    local host="$1"
    puerto_abierto 445 || puerto_abierto 139 || return 0
    echo
    echo -e "${C_BLU}[*] FASE 3C: Reconocimiento SMB${C_RST}"
    usar_termino SMB
    explicar "SMB básico" \
        "Pregunta a SMB el sistema operativo, el nombre del equipo, los dialectos que acepta y si exige firma." \
        "En Windows, SMB revela mucho sin credenciales. SMBv1 activo ya es un hallazgo." \
        "OS y nombre del equipo, la lista de dialectos (busca NT LM 0.12 = SMBv1) y message signing."
    ask_yes_no "¿Ejecutar reconocimiento SMB?" || return 0
    local out="${MACHINE_DIR}/otros/smb_nmap.txt"
    local cmd="nmap -n -Pn -p139,445 --script smb-os-discovery,smb-protocols,smb-security-mode -oN ${out} ${host}"
    imprimir_comando "${cmd}"
    nmap -n -Pn -p139,445 --script smb-os-discovery,smb-protocols,smb-security-mode -oN "${out}" "${host}" || true
    if command -v netexec >/dev/null 2>&1; then
        imprimir_comando "netexec smb ${host}"
        netexec smb "${host}" 2>/dev/null | tee "${MACHINE_DIR}/otros/smb_netexec.txt" || true
    else
        echo -e "${C_YEL}[i] netexec no instalado. Se omite (sudo apt install netexec).${C_RST}"
    fi
    if grep -q "NT LM 0.12" "${out}" 2>/dev/null; then
        echo -e "${C_RED}[!] SMBv1 habilitado. Anótalo como hallazgo.${C_RST}"
        log_info "HALLAZGO: SMBv1 habilitado en ${host}"
    fi
    log_info "SMB básico guardado en ${out}"
}

ftp_anonimo() {
    local host="$1"
    puerto_abierto 21 || return 0
    echo
    echo -e "${C_BLU}[*] FASE 3D: FTP anónimo${C_RST}"
    usar_termino FTP
    explicar "FTP anónimo" \
        "Intenta entrar al FTP con el usuario anonymous y listar la carpeta raíz. No descarga nada." \
        "Muchos servidores dejan el acceso anónimo abierto por error." \
        "Si lista archivos, el acceso anónimo está habilitado. Mira nombres de archivos de notas, respaldos o configuración."
    ask_yes_no "¿Probar FTP anónimo?" || return 0
    local out="${MACHINE_DIR}/otros/ftp_anonimo.txt"
    imprimir_comando "curl -s --max-time 15 --list-only ftp://anonymous:anonymous@${host}/"
    if curl -s --max-time 15 --list-only "ftp://anonymous:anonymous@${host}/" > "${out}" 2>/dev/null; then
        echo -e "${C_RED}[!] FTP anónimo HABILITADO. Contenido de la raíz:${C_RST}"
        sed 's/^/    /' "${out}"
        log_info "HALLAZGO: FTP anónimo habilitado en ${host}. Listado en ${out}"
    else
        echo -e "${C_GRN}[+] FTP anónimo no permitido.${C_RST}"
        rm -f "${out}"
        log_info "FTP anónimo no permitido en ${host}"
    fi
}

modo_imprimir() {
    # Muestra el plan completo sin ejecutar nada
    local ip="IP_OBJETIVO" m="MAQUINA"
    echo -e "${C_BLU}=== MODO PLAN: comandos de cada fase (no se ejecuta nada) ===${C_RST}"
    echo
    echo -e "${C_BOLD}Preparación${C_RST}"
    echo "    ls -lh /usr/share/wordlists/rockyou.txt* ; sudo gzip -dk /usr/share/wordlists/rockyou.txt.gz"
    echo
    echo -e "${C_BOLD}0. Carpeta y objetivo${C_RST}"
    echo "    mkdir -p ${m}/{nmap,exploit,otros}"
    echo "    echo \"${ip}\" > ${m}/target.txt && export IP=\$(<${m}/target.txt)"
    echo "    Por qué: evidencia ordenada desde el inicio."
    echo
    echo -e "${C_BOLD}1. TTL${C_RST}"
    echo "    ping -c 1 ${ip}"
    echo "    Por qué: 64 sugiere Linux, 128 Windows. Si no responde, ICMP puede estar bloqueado."
    echo
    echo -e "${C_BOLD}2. Todos los puertos${C_RST}"
    echo "    sudo nmap -n -Pn -T4 -sS --open -p- -oN ${m}/nmap/allports.nmap ${ip}"
    echo "    Velocidad: -T3 confiable, -T4 rápido. --min-rate N acelera pero puede perder paquetes y puertos."
    echo "    Por qué: los servicios no siempre están en puertos comunes."
    echo
    echo -e "${C_BOLD}3. Versiones${C_RST}"
    echo "    sudo nmap -n -Pn -sV -sC -p<puertos> -oA ${m}/nmap/servicios ${ip}"
    echo "    xsltproc ${m}/nmap/servicios.xml -o ${m}/nmap/servicios.html"
    echo "    searchsploit --nmap ${m}/nmap/servicios.xml"
    echo "    Por qué: la versión exacta dice si hay fallas públicas. Listar no es ejecutar."
    echo
    echo -e "${C_BOLD}3C. SMB (si hay 139/445)${C_RST}"
    echo "    sudo nmap -n -Pn -p139,445 --script smb-os-discovery,smb-protocols,smb-security-mode ${ip}"
    echo "    netexec smb ${ip}"
    echo
    echo -e "${C_BOLD}3D. FTP (si hay 21)${C_RST}"
    echo "    curl --list-only ftp://anonymous:anonymous@${ip}/"
    echo
    echo -e "${C_BOLD}4. Web (si hay 80/443/8080)${C_RST}"
    echo "    whatweb http://${ip}"
    echo "    curl -skI http://${ip}/      # redirige a un dominio? -> /etc/hosts"
    echo "    curl -s http://${ip}/robots.txt"
    echo "    gobuster dir -u http://${ip} -w /usr/share/wordlists/dirb/common.txt -x txt,php,zip -t <hilos> -o ${m}/otros/gobuster.txt"
    echo
    echo "    nikto -h http://${ip} -maxtime 10m -o ${m}/otros/nikto.txt -Format txt   # ruidoso, opcional"
    echo
    echo -e "${C_BOLD}5. Vulnerabilidades (aparte)${C_RST}"
    echo "    sudo nmap -n -Pn --script vuln -p<puertos> -oA ${m}/nmap/vuln ${ip}"
    echo
    echo -e "${C_YEL}Escribe cada comando tú mismo. Entender cada opción vale más que correr el script.${C_RST}"
}

glosario_final() {
    [[ ${#TERMINOS_USADOS[@]} -gt 0 ]] || return 0
    local notas="$1" t
    echo
    echo -e "${C_BLU}=== GLOSARIO DE ESTA SESIÓN ===${C_RST}"
    {
        echo
        echo "## Glosario de la sesión"
    } >> "${notas}"
    for t in "${TERMINOS_USADOS[@]}"; do
        echo "  • $(definir_termino "$t")"
        echo "- $(definir_termino "$t")" >> "${notas}"
    done
}

exportar_evidencia() {
    echo
    explicar "Empaquetar la evidencia" \
        "Comprime toda la carpeta de la máquina en un .tar.gz con fecha y calcula su SHA-256." \
        "Así entregas la evidencia completa y cualquiera puede comprobar que no fue modificada." \
        "El archivo .tar.gz y su .sha256 junto a la carpeta. Para verificar: sha256sum -c <archivo>.sha256"
    ask_yes_no "¿Empaquetar la evidencia ahora?" || return 0
    local paquete
    paquete="evidencia_${MACHINE_NAME}_$(date +%F_%H%M).tar.gz"
    imprimir_comando "tar -czf ${paquete} ${MACHINE_DIR} && sha256sum ${paquete} > ${paquete}.sha256"
    tar -czf "${paquete}" "${MACHINE_DIR}"
    sha256sum "${paquete}" > "${paquete}.sha256"
    chown "${ORIG_USER}:${ORIG_USER}" "${paquete}" "${paquete}.sha256" 2>/dev/null || true
    echo -e "${C_GRN}[+] Evidencia: ${paquete}${C_RST}"
    echo -e "${C_GRN}[+] Huella:    $(cut -d' ' -f1 "${paquete}.sha256")${C_RST}"
    log_info "Evidencia exportada: ${paquete} (SHA-256 en ${paquete}.sha256)"
}

# --- [NUEVO] Generar Reporte Final (Formato Corregido) ---
generar_reporte_final() {
    local notas_file="${MACHINE_DIR}/notashacking_${MACHINE_NAME}.md"
    if [[ -f "${notas_file}" ]]; then
        notas_file="${MACHINE_DIR}/notashacking_${MACHINE_NAME}_$(date +%F_%H%M).md"
        echo -e "${C_YEL}[i] Ya existían notas. No se sobrescriben: se crea ${notas_file}${C_RST}"
    fi
    
    echo
    echo -e "${C_CYN}[*] Generando reporte de trabajo: ${notas_file}...${C_RST}"

    cat > "${notas_file}" <<EOF
# 📝 Notas de Hacking: ${MACHINE_NAME}
**Fecha:** $(date)
**Target IP:** ${TARGET_IP}
**Attacker IP (Tu IP):** ${ATTACKER_IP}

## 1. Reconocimiento de Puertos
| Puerto | Servicio | Detalle/Versión |
|:-------|:---------|:----------------|
EOF

    # Extraer Tabla de Puertos
    if [[ -f "${LOG_FILE}" ]]; then
        grep -E "^[0-9]+/tcp" "${LOG_FILE}" | \
        sed -E 's/syn-ack ttl [0-9]+ //g' | \
        awk '{
            port=$1; service=$3;
            $1=""; $2=""; $3=""; 
            print "| " port " | " service " | " $0 " |"
        }' >> "${notas_file}" || echo "| N/D | N/D | No se encontraron detalles |" >> "${notas_file}"
    fi

    cat >> "${notas_file}" <<EOF

## 2. Enumeración Web
EOF

    # Extraer Web (whatweb, robots, sensibles)
    if [[ -f "${LOG_FILE}" ]]; then
        grep -E "^=== ENUMWEB|Sensible encontrado|WordPress|whatweb" "${LOG_FILE}" >> "${notas_file}" 2>/dev/null || echo "Sin actividad web relevante." >> "${notas_file}"
    fi

    # Comandos de fuzzing/nikto para correr a mano
    {
        echo ""
        echo "### Comandos para ejecutar a mano (fuzzing / nikto)"
        echo "Corre estos en otra terminal. Los puertos ya estan arriba: no hay que esperar al fuzzing."
    } >> "${notas_file}"
    if [[ -f "${MACHINE_DIR}/comandos_pendientes.txt" ]]; then
        {
            echo '```bash'
            cat "${MACHINE_DIR}/comandos_pendientes.txt"
            echo '```'
        } >> "${notas_file}"
    else
        echo "_No se registraron comandos manuales._" >> "${notas_file}"
    fi

    cat >> "${notas_file}" <<EOF

## 3. Análisis de vulnerabilidades (informe sección 2)
- [ ] Automatizado (nmap --script vuln / droid.sh, Nessus):
- [ ] Manual:
- [ ] CVEs con CVSS:
- [ ] CWE:
- [ ] searchsploit: ver nmap/searchsploit.txt

## Guía MQ-HM-RETO (para pasar al informe)
1. Reconocimiento · 2. Análisis de vulnerabilidades · 3. Explotación automatizada y manual · 4. Escalación · 5. Borrado · 6. Banderas · 7. Herramientas · 8. Extra · 9. Conclusiones y recomendaciones

## 4. Credenciales
|      Usuario      |      Password      |      Hash      |      Servicio      |
|-------------------|-------------------|---------------|-------------------|
|                   |                   |               |                   |

## 5. Flags
- [ ] User Flag:
- [ ] Root Flag:


## 6. Otras

























EOF

    glosario_final "${notas_file}"
    printf '\n---\n*Generado por Yautja by 0xAlienSec*\n' >> "${notas_file}"
    chown "${ORIG_USER}:${ORIG_USER}" "${notas_file}"
    echo
    echo -e "${C_GRN}[+] Reporte listo y pre-rellenado: ${notas_file}${C_RST}"
}

# --- [6] Main ---
main() {
    while getopts ":yqph" opt; do
        case "$opt" in
            y) MODO_AUTO=1 ;;
            p) MODO_IMPRIMIR=1 ;;
            q) MODO_EXPLICAR=0 ;;
            h) uso; exit 0 ;;
            *) uso; exit 1 ;;
        esac
    done
    if [[ "${MODO_IMPRIMIR}" -eq 1 ]]; then
        modo_imprimir
        exit 0
    fi
    check_deps
    check_root
    panel_target ""
    show_banner
    preparar_panel
    configurar_maquina
    leer_ip_objetivo

    log_info "INICIO DE ESCANEO"

    revisar_rockyou

    detectar_ttl_y_os "${TARGET_IP}"
    pausa
    escaneo_nmap_rapido "${TARGET_IP}"
    pausa

    if [[ -n "${OPEN_PORTS_CSV}" ]]; then
        if ask_yes_no "¿Escanear versiones (-sV -sC)?"; then
            escaneo_nmap_agresivo "${TARGET_IP}" "${OPEN_PORTS_CSV}"
        fi
        enum_smb_basico "${TARGET_IP}"
        ftp_anonimo "${TARGET_IP}"
        generar_droide_vuln "${TARGET_IP}" "${OPEN_PORTS_CSV}"
    fi

    echo
    echo -e "${C_GRN}[i] Puertos detectados:${C_RST} ${OPEN_PORTS_CSV:-Ninguno}"
    local sugeridos
    sugeridos=$(echo "${OPEN_PORTS_CSV}" | tr ',' '\n' | grep -xE '80|443|8000|8080|8443|3333|8888' | paste -sd ',' - || true)
    [[ -n "${sugeridos}" ]] && echo -e "${C_CYN}[i] Posibles puertos web: ${sugeridos}${C_RST}"

    if ask_yes_no "¿Ejecutar ENUMWEB en puertos específicos?"; then
        echo -en "${C_YEL}[?] Puertos (ej: 80,8080): ${C_RST}"
        read -r http_ports_input || true
        
        http_ports_input="${http_ports_input// /}"
        IFS=',' read -r -a HTTP_PORTS <<< "${http_ports_input}"

        for port in "${HTTP_PORTS[@]}"; do
            [[ -z "${port}" ]] && continue
            if [[ ! "${port}" =~ ^[0-9]+$ ]]; then
                echo -e "${C_RED}[!] ${port} no es un número de puerto válido.${C_RST}"
                continue
            fi
            enum_web_port "${TARGET_IP}" "${port}"
        done
    fi

    log_info "FIN DE ESCANEO"
    chown -R "${ORIG_USER}:${ORIG_USER}" "${MACHINE_DIR}" 2>/dev/null || true
    
    # Generar Reporte Final
    usar_termino HASH
    generar_reporte_final

    echo
    echo -e "${C_GRN}[i] Log de Auditoría (Insumo Completo): ${LOG_FILE}${C_RST}"
    echo
    echo -e "${C_BLU}=== RESUMEN ===${C_RST}"
    echo -e "  Objetivo:        ${TARGET_IP}"
    echo -e "  Puertos:         ${OPEN_PORTS_CSV:-Ninguno}"
    echo -e "  Evidencia nmap:  ${OUTPUT_DIR}/"
    [[ -s "${MACHINE_DIR}/comandos_pendientes.txt" ]] && echo -e "  Pendientes:      ${MACHINE_DIR}/comandos_pendientes.txt (nikto y otros para correr aparte)"
    echo -e "  Notas:           ${MACHINE_DIR}/notashacking_${MACHINE_NAME}*.md"
    echo -e "  Tiempo total:    $(( $(date +%s) - T_INICIO )) s"
    echo -e "${C_YEL}  Siguiente paso: lee las versiones, revisa searchsploit y, si quieres, corre droid.sh aparte.${C_RST}"
    exportar_evidencia
    echo -e "${C_BLU}=== 4l13N IS HERE ===${C_RST}"
}

main "$@"
