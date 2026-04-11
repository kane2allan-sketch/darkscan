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

    # Sanitizar nombre del target para archivos
    target_clean = args.target.replace("https://", "").replace("http://", "").replace("/", "_").strip("_")
    os.makedirs("reports", exist_ok=True)

    print(f"\n{'='*60}")
    print(f"[*] DarkScan v1.3 iniciando sobre: {args.target}")
    print(f"{'='*60}")
    
    # 1. RECONOCIMIENTO
    fp = Fingerprinter(args.target, "data/signatures/web_tech.json", {})
    results = await fp.analyze()

    if not results or "error" in results[0]:
        print("[!] Error en el escaneo inicial. Abortando.")
        return

    print("\n[+] Tecnologías Detectadas:")
    for res in results:
        print(f"    - {res['technology']:<12} [v{res['version']:<10}] [Confianza: {res['confidence']}]")
    
    # 2. FUZZING
    fuzzer = SmartFuzzer(args.target, results, {})
    fuzz_matches = await fuzzer.run()
    if fuzz_matches:
        print("\n[!] Hallazgos en Fuzzing:")
        for match in fuzz_matches:
            print(f"    [{match['status']}] {match['path']}")

    # 3. VULNERABILIDADES (BAJO DEMANDA)
    if args.nist or args.snyk:
        nist_key = args.nist if args.nist != "NO_KEY" else None
        mapper = VulnMapper(nist_key=nist_key, snyk_key=args.snyk)
        
        print("\n[!] Fase de Vulnerabilidades Activada:")

        for res in results:
            tech, ver = res['technology'], res['version']
            if ver == "Unknown":
                continue

            # Manejo de NIST
            if args.nist:
                print(f"    [*] Consultando NIST para {tech} {ver}...")
                nist_vulns = await mapper.check_nist(tech, ver)
                if nist_vulns:
                    file_path = f"reports/{target_clean}_nist.txt"
                    with open(file_path, "a") as f:
                        f.write(f"\n{'='*20} {tech} {ver} {'='*20}\n")
                        f.writelines(nist_vulns)
                    print(f"    [OK] {len(nist_vulns)} hallazgos guardados en {file_path}")

            # Manejo de Snyk
            if args.snyk:
                print(f"    [*] Consultando Snyk para {tech} {ver}...")
                snyk_vulns = await mapper.check_snyk(tech, ver)
                if snyk_vulns:
                    file_path = f"reports/{target_clean}_snyk.txt"
                    with open(file_path, "a") as f:
                        f.write(f"\n{'='*20} {tech} {ver} {'='*20}\n")
                        f.writelines(snyk_vulns)
                    print(f"    [OK] {len(snyk_vulns)} hallazgos guardados en {file_path}")

    print(f"\n{'='*60}")
    print("[*] Tarea finalizada. Revisa la carpeta 'reports/' para detalles.")

if __name__ == "__main__":
    asyncio.run(main())
