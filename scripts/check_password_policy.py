#!/usr/bin/env python3
"""
Verifica la política de contraseñas del sistema en Linux,
macOS y Windows.
- En Linux se lee /etc/security/pwquality.conf y se extrae
  el parámetro "minlen".
- En macOS se usa "pwpolicy -getaccountpolicies" para extraer
  "POLICY_MIN_COMPLEXITY".
- En Windows se ejecuta "net accounts" y se extrae la línea
  "Minimum password length".
El script compara el valor obtenido con un mínimo requerido
(REQ_MIN_LENGTH) y notifica si la política cumple ese
estándar.
"""

import subprocess
import logging
import re
import platform
import os

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)

REQ_MIN_LENGTH = 8


def get_policy_output():
    """
    Detecta el sistema operativo y ejecuta el comando
    adecuado para obtener la política de contraseñas.
    Retorna una tupla (output, os_type).
    """
    os_type = platform.system()

    if os_type == "Linux":
        if os.path.exists("/etc/security/pwquality.conf"):
            command = ["cat", "/etc/security/pwquality.conf"]
        else:
            if os.path.exists("/etc/pam.d/common-password"):
                command = ["cat", "/etc/pam.d/common-password"]
            else:
                logging.error(
                    "No se encontró archivo de "
                    "configuración"
                )
                return None, os_type
    elif os_type == "Darwin":
        command = ["pwpolicy", "-getaccountpolicies"]
    elif os_type == "Windows":
        command = ["net", "accounts"]
    else:
        logging.error(f"Sistema no soportado: {os_type}")
        return None, os_type

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout, os_type
    except subprocess.CalledProcessError as e:
        logging.error(
            f"Error al ejecutar comando en {os_type}: {e}"
        )
        logging.debug(f"Error detallado: {e.stderr}")
        return None, os_type
    except FileNotFoundError:
        logging.error(f"Comando no encontrado para {os_type}.")
        return None, os_type


def parse_policy_linux(output):
    """
    Extrae la longitud mínima (minlen) del archivo de
    configuración en Linux.
    """
    match = re.search(
        r"^\s*minlen\s*=\s*(\d+)",
        output,
        re.MULTILINE
    )
    if match:
        return int(match.group(1))

    match = re.search(
        r"password\s+requisite\s+"
        r"(?:pam_cracklib|pam_pwquality).so.*"
        r"minlen=(\d+)",
        output
    )
    if match:
        return int(match.group(1))

    match = re.search(r"minlen=(\d+)", output)
    if match:
        return int(match.group(1))

    return None


def parse_policy_macos(output):
    """
    Extrae POLICY_MIN_COMPLEXITY de la salida de pwpolicy
    en macOS.
    """
    match = re.search(
        r'POLICY_MIN_COMPLEXITY\s*=\s*"?(\d+)"?',
        output
    )
    if match:
        return int(match.group(1))

    match = re.search(
        r'minChars\s*=\s*"?(\d+)"?',
        output
    )
    if match:
        return int(match.group(1))

    return None


def parse_policy_windows(output):
    """
    Extrae "Minimum password length" de la salida.
    """
    match = re.search(
        r"Minimum password length\s*:?\s*(\d+)",
        output,
        re.IGNORECASE
    )
    if match:
        return int(match.group(1))
    return None


def analyze_policy():
    """
    Función principal que obtiene, parsea y analiza la
    política de contraseñas.
    """
    logging.info("Iniciando verificación de la política...")

    output, os_type = get_policy_output()
    if output is None:
        logging.error("No se pudo obtener la política.")
        return

    logging.debug(f"Salida obtenida: {output}")

    if os_type == "Linux":
        min_value = parse_policy_linux(output)
        policy_param = "minlen (Linux)"
    elif os_type == "Darwin":
        min_value = parse_policy_macos(output)
        policy_param = "POLICY_MIN_COMPLEXITY (macOS)"
    elif os_type == "Windows":
        min_value = parse_policy_windows(output)
        policy_param = "Minimum password length (Win)"
    else:
        logging.warning(
            f"No se pudo extraer valor de política en {os_type}."
        )
        return

    if min_value is None:
        logging.warning(
            f"No se pudo extraer valor de política en {os_type}."
        )
        return

    logging.info(
        f"Se encontró {policy_param}: {min_value}"
    )
    if min_value < REQ_MIN_LENGTH:
        logging.warning(
            f"El valor ({min_value}) es inferior al mínimo "
            f"requerido ({REQ_MIN_LENGTH})."
        )
    else:
        logging.info(
            "La política cumple el mínimo requerido."
        )

    logging.info("Verificación completada.")


def main():
    analyze_policy()


if __name__ == "__main__":
    main()
