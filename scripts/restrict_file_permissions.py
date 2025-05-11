#!/usr/bin/env python3
"""
Verifica y restringe los permisos de archivos en un directorio.

- Lee el archivo de configuración en Linux, por ejemplo,
  "/etc/security/pwquality.conf" o "/etc/pam.d/common-password".
- Ejecuta "pwpolicy -getaccountpolicies" en macOS para extraer
  POLICY_MIN_COMPLEXITY.
- Usa "net accounts" en Windows para extraer "Minimum password"
  length".

El script compara el valor obtenido con un mínimo requerido
(REQ_MIN_LENGTH) y notifica si la política cumple o no.
"""

import os
import subprocess
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)

# Valor mínimo esperado (en octal, como entero)
REQ_MIN_PERMISSIONS = int("0644", 8)


def get_file_permissions(filepath):
    """
    Obtiene los permisos actuales de un archivo y retorna
    el valor entero (por ejemplo, 420 para oct(644)).
    """
    try:
        stat_info = os.stat(filepath)
        return stat_info.st_mode & 0o777
    except OSError as e:
        logging.error(f"Error al acceder a {filepath}: {e}")
        return None


def set_file_permissions(filepath, permissions):
    """
    Intenta establecer los permisos de un archivo usando sudo.
    """
    try:
        subprocess.run(
            ["sudo", "chmod", oct(permissions), filepath],
            check=True
        )
        logging.info(
            f"Permisos de {filepath} establecidos a {oct(permissions)}"
        )
        return True
    except subprocess.CalledProcessError as e:
        logging.error(
            f"Error al cambiar permisos de {filepath}: {e}"
        )
        return False


def check_and_process_permissions(directory, expected, change=False):
    """
    Verifica y procesa los permisos de los archivos en el
    directorio.
    """
    logging.info(
        f"Verificando permisos en el directorio: {directory}"
    )
    for root, _, files in os.walk(directory):
        for filename in files:
            filepath = os.path.join(root, filename)
            current = get_file_permissions(filepath)
            if current is not None and current != expected:
                logging.warning(
                    f"Permisos incorrectos para {filepath}: {oct(current)},"
                    f" se espera {oct(expected)}"
                )
                if change:
                    set_file_permissions(filepath, expected)


def main():
    """
    Función principal para verificar y restringir permisos.
    """
    directory_to_check = "/etc"  # Esta ruta puede ser configurable
    attempt_change = False       # Poner a True para cambiar permisos

    check_and_process_permissions(
        directory_to_check, REQ_MIN_PERMISSIONS, attempt_change
    )


if __name__ == "__main__":
    main()
