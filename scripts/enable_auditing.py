#!/usr/bin/env python3
"""Verifica si el sistema de auditoría (auditd) está instalado,
habilitado y lo inicia si es necesario."""

import subprocess
import logging
import time

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def is_auditd_installed():
    """Verifica si auditd está instalado en el sistema."""
    try:
        result = subprocess.run(
            ["which", "auditd"],
            capture_output=True,
            text=True,
            check=True
        )
        if result.stdout.strip():
            logging.info("El servicio auditd está instalado.")
            return True
        else:
            logging.warning("El servicio auditd no está instalado.")
            return False
    except subprocess.CalledProcessError as e:
        logging.error(f"Error al verificar si auditd está instalado: {e}")
        return False


def get_auditd_status():
    """Ejecuta el comando para obtener el estado de auditd."""
    try:
        result = subprocess.run(
            ["sudo", "systemctl", "is-active", "auditd"],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"Error al verificar el estado de auditd: {e}")
        return None


def start_auditd():
    """Intenta iniciar el servicio auditd."""
    try:
        subprocess.run(
            ["sudo", "systemctl", "start", "auditd"],
            capture_output=True,
            text=True,
            check=True
        )
        logging.info("El servicio auditd se inició correctamente.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error al intentar iniciar auditd: {e}")


def main(max_attempts=3, delay=5):
    """Función principal para verificar y, si es necesario, iniciar auditd."""
    if not is_auditd_installed():
        logging.error(
            "El servicio auditd no está instalado."
            " Por favor, instálalo antes de continuar."
            )
        return

    attempt = 0
    while attempt < max_attempts:
        logging.info("Verificando el estado del servicio auditd...")
        status = get_auditd_status()
        if status == "active":
            logging.info("El servicio auditd ya está activo.")
            return
        elif status is None:
            logging.error("No se pudo determinar el estado de auditd.")
            return
        else:
            logging.warning("Advertencia: El servicio auditd no está activo.")
            logging.info("Intentando iniciar el servicio auditd...")
            start_auditd()
            time.sleep(delay)
            attempt += 1


logging.error(
    "No se pudo activar el servicio auditd"
    " después de varios intentos.")


if __name__ == "__main__":
    main()
