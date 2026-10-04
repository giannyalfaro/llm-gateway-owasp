"""Muestra qué capturas de evidencia (.png) faltan en evidencias/.

Uso:  python scripts\\evidencias.py
"""
import sys
from pathlib import Path

sys.stdout.reconfigure(errors="replace")

CARPETA = Path(__file__).resolve().parent.parent / "evidencias"

# (archivo, fase, qué debe verse)
EVIDENCIAS = [
    ("01_baseline_llm01_inyeccion.png", "F1", "Salida de 'jailbreak' con 'Resumen: X de 7' y tokens consumidos"),
    ("02_baseline_llm10_rafaga.png", "F1", "Salida de 'burst' con '10 x 200 | 0 x 429'"),
    ("03_baseline_llm02_log_filtra.png", "F1", "Consola del servidor con prompt con DNI y key FALSA gsk_FAKE_..."),
    ("04_escudo_llm01_bloqueo_400.png", "F2", "Los 7 ataques con HTTP 400 y 0 tokens consumidos"),
    ("05_escudo_llm01_tests_verde.png", "F2", "pytest tests\\test_llm01_injection.py en verde"),
    ("06_escudo_llm10_429.png", "F3", "Cinco veces 200 y luego 429"),
    ("07_escudo_llm10_tests_verde.png", "F3", "pytest tests\\test_llm10_ratelimit.py en verde"),
    ("08_escudo_llm02_log_json_redactado.png", "F4", "Logs JSON con [REDACTED_KEY], sin prompt crudo"),
    ("09_escudo_llm02_error_generico.png", "F4", "Cliente recibe error generico (502 upstream) sin traza ni rutas"),
    ("10_escudo_llm02_tests_verde.png", "F4", "pytest tests\\test_llm02_credentials.py en verde"),
    ("11_pytest_todos_verde.png", "F4", "pytest completo, todos los tests en verde"),
    ("12_escudo_llm07_system_prompt.png", "Opcional", "Solo si se hace LLM07 en el buffer"),
]


def main():
    print(f"Carpeta: {CARPETA}\n")
    hechas = 0
    obligatorias = [e for e in EVIDENCIAS if e[1] != "Opcional"]
    for nombre, fase, desc in EVIDENCIAS:
        ok = (CARPETA / nombre).exists()
        hechas += ok and fase != "Opcional"
        marca = "[X]" if ok else "[ ]"
        print(f"{marca} {nombre}\n      {fase:<8} {desc}")
    print(f"\nObligatorias: {hechas} de {len(obligatorias)}")
    print("Antes de guardar: que NO se vea tu key real en ninguna captura.")


if __name__ == "__main__":
    main()
