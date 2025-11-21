#!/usr/bin/env bash
#
#   TTL & Port Scanner :: by 0xAlienSec (v7-optimized)
#
#   Scanner interactivo con reporte HTML automático:
#   1. Detección de OS (TTL) y escaneo SYN ultra-rápido.
#   2. Pregunta interactiva para escaneo profundo (-sV -sC).
#   3. Generación de reporte HTML automático (vía xsltproc).
#
set -euo pipefail

# --- [0] Configuración Global ---
C_RST="\e[0m"
C_RED="\e[31m"
C_GRN="\e[32m"
C_YEL="\e[33m"
C_BLU="\e[34m"
C_CYN="\e[36m"

TARGET_IP=""

trap 'echo -e "\n\n${C_YEL}[!] Escaneo interrumpido.${C_RST}"; exit 1' INT

# --- [1] Funciones de Ayuda y Banner ---
show_help() {
    echo -e "${C_GRN}Uso:${C_RST} sudo $0 <IP_OBJETIVO>"
    echo
    echo -e "${C_YEL}Opciones:${C_RST}"
    echo -e "  ${C_CYN}-h${C_RST}         Muestra este menú de ayuda."
    echo
    echo -e "${C_YEL}Ejemplo:${C_RST}"
    echo -e "  sudo $0 10.10.10.5"
    exit 0
}

show_banner() {
    echo -e "${C_BLU}===============================================${C_RST}"
    echo -e "   ${C_GRN}TTL & Port Scanner${C_RST} :: ${C_YEL}by 0xAlienSec${C_RST}"
    echo -e "${C_BLU}===============================================${C_RST}"
    echo
}

# --- [2] Funciones de Validación ---
check_deps() {
    for cmd in ping nmap awk grep cut sudo xsltproc; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo -e "${C_RED}[-] Comando requerido no encontrado: $cmd${C_RST}"
            if [[ "$cmd" == "xsltproc" ]]; then
                echo -e "${C_YEL}[*] Sugerencia: prueba 'sudo apt install xsltproc' (Debian/Ubuntu) o 'sudo dnf install libxslt' (Fedora)${C_RST}"
            fi
            exit 1
        fi
    done
}

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo -e "${C_RED}[-] Este script requiere privilegios de root para -sS (SYN Scan).${C_RST}"
        echo -e "${C_YEL}[*] Por favor, ejecútalo con 'sudo'${C_RST}"
        exit 1
    fi
}

# --- [3] Funciones de Escaneo ---
detectar_ttl_y_os() {
    local host="$1"
    local ttl
    echo -e "${C_BLU}[*] FASE 1: Identificación de TTL y SO...${C_RST}"

    ttl=$(ping -c1 -W1 "$host" 2>/dev/null | awk -F'ttl=' '/ttl=/{split($2,a," "); print a[1]; exit}')

    if [[ -z "${ttl}" ]]; then
        echo -e "${C_YEL}[!] Sin respuesta ICMP (Host discovery -Pn será usado por Nmap).${C_RST}"
        return
    fi

    local os="Desconocido"
    if   (( ttl <= 64 ));  then os="Unix/Linux (TTL: ${ttl})"
    elif (( ttl <= 128 )); then os="Windows (TTL: ${ttl})"
    else                       os="Router/Dispositivo (TTL: ${ttl})"
    fi
    echo -e "${C_GRN}[+] SO Probable: ${os}${C_RST}"
}

escaneo_nmap_rapido() {
    local host="$1"
    local temp_xml="temp_fast_scan.xml"
    
    echo -e "${C_BLU}[*] FASE 2: Escaneo SYN rápido de puertos...${C_RST}"
    echo -e "    ${C_CYN}nmap -sS -sV --open -p- -n -Pn --min-rate 3000 -oX ${temp_xml} ${host}${C_RST}"
    echo

    # Escaneo con detección básica de servicios (sin output a pantalla)
    nmap -sS -sV --open -p- -n -Pn --min-rate 3000 -oX "${temp_xml}" "${host}" > /dev/null 2>&1

    # Extraer puertos, servicios y versiones del XML
    if [[ ! -f "${temp_xml}" ]]; then
        echo -e "${C_RED}[-] No se pudo generar el archivo temporal XML.${C_RST}"
        return
    fi

    # Parsear XML para obtener información detallada
    local ports_info
    ports_info=$(grep -E '<port protocol="tcp".*state="open"' "${temp_xml}" -A 5 | \
                 awk '/<port protocol="tcp"/{
                     match($0, /portid="([0-9]+)"/, port);
                     p=port[1];
                 }
                 /<service name="/{
                     match($0, /name="([^"]+)"/, svc);
                     match($0, /product="([^"]+)"/, prod);
                     match($0, /version="([^"]+)"/, ver);
                     service=svc[1];
                     product=(prod[1] ? prod[1] : "");
                     version=(ver[1] ? ver[1] : "");
                     if(product != "" && version != "")
                         printf "%s\t%s\t%s %s\n", p, service, product, version;
                     else if(product != "")
                         printf "%s\t%s\t%s\n", p, service, product;
                     else
                         printf "%s\t%s\t-\n", p, service;
                 }')

    # Limpiar archivo temporal
    rm -f "${temp_xml}"

    if [[ -z "${ports_info}" ]]; then
        echo -e "${C_GRN}[+] No se detectaron puertos abiertos.${C_RST}"
        return
    fi

    echo
    echo -e "${C_GRN}[+] Puertos Abiertos con Servicios Detectados:${C_RST}"
    echo -e "${C_CYN}┌────────┬──────────────┬────────────────────────────────────────┐${C_RST}"
    echo -e "${C_CYN}│ PUERTO │ SERVICIO     │ VERSIÓN                                │${C_RST}"
    echo -e "${C_CYN}├────────┼──────────────┼────────────────────────────────────────┤${C_RST}"
    
    while IFS=$'\t' read -r port service version; do
        printf "${C_CYN}│${C_RST} %-6s ${C_CYN}│${C_RST} %-12s ${C_CYN}│${C_RST} %-38s ${C_CYN}│${C_RST}\n" "$port" "$service" "$version"
    done <<< "$ports_info"
    
    echo -e "${C_CYN}└────────┴──────────────┴────────────────────────────────────────┘${C_RST}"
    echo

    # Obtener lista CSV de puertos
    local puertos_csv
    puertos_csv=$(echo "${ports_info}" | cut -f1 | paste -sd ',' -)
    
    echo -e "${C_GRN}[+] Puertos (CSV): ${C_YEL}${puertos_csv}${C_RST}"
    echo
    
    local choice
    echo -e -n "${C_YEL}[?] ¿Deseas realizar un escaneo profundo con scripts (-sC)? (s/N): ${C_RST}"
    read -r choice

    case "${choice,,}" in
        s|si|y|yes|1)
            escaneo_nmap_agresivo "${host}" "${puertos_csv}"
            ;;
        *)
            echo -e "${C_YEL}[*] Omitiendo escaneo profundo.${C_RST}"
            ;;
    esac
}

escaneo_nmap_agresivo() {
    local host="$1"
    local port_list="$2"

    if [[ -z "${port_list}" ]]; then
        return
    fi

    # Definimos los nombres de archivo
    local output_filename="${host}_deep_scan"
    local xml_input="${output_filename}.xml"
    local html_output="${output_filename}.html"

    echo
    echo -e "${C_BLU}[*] FASE 3: Escaneo Profundo (Scripts, Versión Detallada)...${C_RST}"
    echo -e "    ${C_CYN}nmap -sV -sC -vvv -Pn --min-rate 3000 -p${port_list} -oA ${output_filename} ${host}${C_RST}"
    echo
    
    # Ejecuta el escaneo Nmap
    nmap -sV -sC -vvv -Pn --min-rate 3000 -p"${port_list}" -oA "${output_filename}" "${host}"

    echo
    echo -e "${C_GRN}[+] ¡Escaneo profundo completado!${C_RST}"
    echo -e "${C_GRN}[+] Resultados Nmap guardados en: ${output_filename}.(nmap|xml|gnmap)${C_RST}"

    # --- FASE 4: Generación de Reporte HTML ---
    echo
    echo -e "${C_BLU}[*] FASE 4: Generando reporte HTML desde XML...${C_RST}"
    
    if [[ -f "${xml_input}" ]]; then
        echo -e "    ${C_CYN}xsltproc ${xml_input} -o ${html_output}${C_RST}"
        xsltproc "${xml_input}" -o "${html_output}"
        
        echo -e "${C_GRN}[+] ¡Reporte HTML generado!${C_RST}"
        echo -e "${C_GRN}[+] Archivo: ${html_output}${C_RST}"
    else
        echo -e "${C_RED}[-] No se encontró el archivo ${xml_input}. No se pudo generar el reporte HTML.${C_RST}"
    fi
}

# --- [4] Flujo Principal ---
main() {
    while getopts "h" opt; do
        case $opt in
            h) show_help ;;
            *) show_help ;;
        esac
    done
    shift $((OPTIND - 1))

    # --- Validaciones ---
    check_deps
    check_root
    show_banner

    # --- Obtener IP ---
    if [[ $# -eq 0 ]]; then
        echo -e "${C_RED}[-] No se proporcionó IP objetivo.${C_RST}"
        show_help
    fi
    TARGET_IP="$1"
    echo -e "${C_YEL}[*] Objetivo: ${TARGET_IP}${C_RST}"
    echo

    # --- Ejecución ---
    detectar_ttl_y_os "${TARGET_IP}"
    echo

    escaneo_nmap_rapido "${TARGET_IP}"
    
    echo
    echo -e "${C_BLU}===============================================${C_RST}"
    echo -e "   ${C_GRN}Escaneo Finalizado${C_RST}"
    echo -e "${C_BLU}===============================================${C_RST}"
}

main "$@"