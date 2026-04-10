import asyncio
import argparse
import sys
import os

# Asegurar que el path del proyecto sea reconocido para las importaciones
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules.recon.fingerprinter import Fingerprinter
from modules.fuzzer.fuzzer import SmartFuzzer
from modules.vulnerability.scanner import VulnMapper

async def main():
    parser = argparse.ArgumentParser(description="DarkScan - Pentesting Framework v1.2")
    parser.add_argument("-t", "--target", help="URL objetivo (ej: https://example.com)", required=True)
    parser.add_argument("-c", "--cookie", help="Cookie de sesión (nombre=valor)", default=None)
    parser.add_argument("-k", "--key", help="NIST NVD API Key (opcional)", default=None)
    args = parser.parse_args()

    # Procesar Cookies
    cookies = {}
    if args.cookie:
        try:
            c_name, c_val = args.cookie.split('=', 1)
            cookies[c_name] = c_val
        except ValueError:
            print("[!] Error: El formato de la cookie debe ser nombre=valor")
            return

    print(f"\n{'='*60}")
    print(f"[*] DarkScan v1.2 iniciando sobre: {args.target}")
    print(f"{'='*60}")
    
    # --- FASE 1: RECONOCIMIENTO (FINGERPRINTING) ---
    fp = Fingerprinter(args.target, "data/signatures/web_tech.json", cookies)
    results = await fp.analyze()

    if results and isinstance(results, list) and "error" not in results[0]:
        print("\n[+] Tecnologías Detectadas:")
        for res in results:
            # Formateo limpio de la confianza y versión
            conf = res['confidence']
            print(f"    - {res['technology']:<12} [v{res['version']:<10}] [Confianza: {conf}]")
        
        # --- FASE 2: FUZZING INTELIGENTE ---
        fuzzer = SmartFuzzer(args.target, results, cookies)
        fuzz_matches = await fuzzer.run()
        
        if fuzz_matches:
            print("\n[!] Hallazgos interesantes en el Fuzzing:")
            for match in sorted(fuzz_matches, key=lambda x: x['status']):
                print(f"    [{match['status']}] {match['path']} -> {match['note']}")
        else:
            print("\n[*] Fuzzing completado sin hallazgos públicos.")

        # --- FASE 3: MAPEO DE VULNERABILIDADES (NIST NVD) ---
        mapper = VulnMapper(api_key=args.key)
        
        print("\n[!] Consultando Base de Datos NIST (NVD)...")
        found_vulns = False
        
        for res in results:
            if res['version'] != "Unknown":
                # Consulta asíncrona a la API de NIST
                matches = await mapper.check(res['technology'], res['version'])
                
                if matches:
                    if "error" in matches[0]:
                        print(f"    [!] Error en {res['technology']}: {matches[0]['error']}")
                    else:
                        print(f"\n[+] Vulnerabilidades para {res['technology']} {res['version']}:")
                        found_vulns = True
                        for m in matches:
                            print(f"    - [{m['severity']}] {m['cve']}: {m['title']}")
            else:
                print(f"    [*] Saltando {res['technology']}: Versión desconocida para NIST.")
        
        if not found_vulns and any(r['version'] != "Unknown" for r in results):
            print("    [*] No se encontraron CVEs críticos recientes para las versiones detectadas.")

    elif results and "error" in results[0]:
        print(f"\n[!] Error en el escaneo: {results[0]['error']}")
    else:
        print("\n[!] No se pudo extraer información del objetivo.")

    print(f"\n{'='*60}")
    print("[*] Tarea finalizada con éxito.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Escaneo abortado por el usuario.")
        sys.exit(0)
