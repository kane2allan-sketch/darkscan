import asyncio
import argparse
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules.recon.fingerprinter import Fingerprinter
from modules.fuzzer.fuzzer import SmartFuzzer
from modules.vulnerability.scanner import VulnMapper

async def main():
    parser = argparse.ArgumentParser(description="DarkScan - Pentesting Framework v1.3")
    parser.add_argument("-t", "--target", help="URL objetivo", required=True)
    parser.add_argument("-c", "--cookie", help="Cookie de sesión (nombre=valor)", default=None)
    parser.add_argument("--nist", help="Activar NIST NVD (opcional: API Key)", nargs='?', const="NO_KEY")
    parser.add_argument("--snyk", help="Activar Snyk (requiere API Token)", default=None)
    args = parser.parse_args()

    # Sanitizar nombre del target para crear archivos legibles
    target_clean = args.target.replace("https://", "").replace("http://", "").replace("/", "_").strip("_")
    os.makedirs("reports", exist_ok=True)

    print(f"\n{'='*60}")
    print(f"[*] DarkScan v1.3 iniciando sobre: {args.target}")
    print(f"{'='*60}")
    
    # --- FASE 1: RECONOCIMIENTO ---
    fp = Fingerprinter(args.target, "data/signatures/web_tech.json", {})
    results = await fp.analyze()

    if not results or (isinstance(results, list) and "error" in results[0]):
        print("[!] Error en el escaneo inicial. Verifica la conectividad al objetivo.")
        return

    print("\n[+] Tecnologías Detectadas:")
    for res in results:
        print(f"    - {res['technology']:<12} [v{res['version']:<10}] [Confianza: {res['confidence']}]")
    
    # --- FASE 2: FUZZING INTELIGENTE ---
    fuzzer = SmartFuzzer(args.target, results, {})
    fuzz_matches = await fuzzer.run()
    if fuzz_matches:
        print("\n[!] Hallazgos en Fuzzing:")
        for match in sorted(fuzz_matches, key=lambda x: x['status']):
            print(f"    [{match['status']}] {match['path']} -> {match['note']}")

    # --- FASE 3: MAPEO DE VULNERABILIDADES (ARCHIVOS) ---
    if args.nist or args.snyk:
        nist_key = args.nist if args.nist != "NO_KEY" else None
        mapper = VulnMapper(nist_key=nist_key, snyk_key=args.snyk)
        
        print("\n[!] Fase de Vulnerabilidades Activada (Generando reportes físicos)...")

        for res in results:
            tech, ver = res['technology'], res['version']
            if ver == "Unknown":
                continue

            # Consulta NIST
            if args.nist:
                print(f"    [*] Consultando NIST para {tech} v{ver}...")
                nist_vulns = await mapper.check_nist(tech, ver)
                if nist_vulns:
                    file_path = f"reports/{target_clean}_nist.txt"
                    with open(file_path, "a", encoding="utf-8") as f:
                        f.write(f"\n{'='*20} {tech} {ver} {'='*20}\n")
                        f.writelines(nist_vulns)
                    
                    # Contamos solo los que no son mensajes de error
                    valid_vulns = [v for v in nist_vulns if not v.startswith("[*]") and not v.startswith("[!]") ]
                    if valid_vulns:
                        print(f"        [+] {len(valid_vulns)} CVEs guardados en {file_path}")
                    else:
                        print(f"        [-] {nist_vulns[0].strip()}")

            # Consulta Snyk
            if args.snyk:
                print(f"    [*] Consultando Snyk para {tech} v{ver}...")
                snyk_vulns = await mapper.check_snyk(tech, ver)
                if snyk_vulns:
                    file_path = f"reports/{target_clean}_snyk.txt"
                    with open(file_path, "a", encoding="utf-8") as f:
                        f.write(f"\n{'='*20} {tech} {ver} {'='*20}\n")
                        f.writelines(snyk_vulns)
                    
                    valid_vulns = [v for v in snyk_vulns if not v.startswith("[*]") and not v.startswith("[!]") ]
                    if valid_vulns:
                        print(f"        [+] {len(valid_vulns)} Issues guardados en {file_path}")
                    else:
                        # Imprime el mensaje de "No encontrado" o "No mapeado"
                        print(f"        [-] {snyk_vulns[0].strip()}")

    print(f"\n{'='*60}")
    print("[*] Tarea finalizada con éxito.")
    if args.nist or args.snyk:
        print("[*] Revisa la carpeta 'reports/' para ver los detalles de las vulnerabilidades.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Escaneo abortado por el usuario.")
        sys.exit(0)
