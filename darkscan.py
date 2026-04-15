import asyncio
import argparse
import sys
import os

# Asegurar que el motor encuentre los módulos locales
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules.recon.fingerprinter import Fingerprinter
from modules.fuzzer.fuzzer import SmartFuzzer
from modules.vulnerability.scanner import VulnMapper
from modules.exploit.verifier import ExploitVerifier

async def main():
    parser = argparse.ArgumentParser(description="DarkScan - Professional Pentesting Framework v1.4.1")
    parser.add_argument("-t", "--target", help="URL objetivo", required=True)
    parser.add_argument("-c", "--cookie", help="Cookie de sesión (nombre=valor)", default=None)
    parser.add_argument("--nist", help="Activar NIST NVD", nargs='?', const="NO_KEY")
    parser.add_argument("--snyk", help="Activar Snyk (Token)", default=None)
    
    # Parámetros de Fuzzing
    parser.add_argument("-f", "--fuzz", help="Ejecutar fuzzing inteligente", action="store_true")
    parser.add_argument("-df", "--deep-fuzz", help="Deep Fuzz o ruta personalizada", 
                        nargs='?', const="DEEP_MODE", default=None)
    
    args = parser.parse_args()

    cookies = {}
    if args.cookie:
        try:
            c_name, c_val = args.cookie.split('=', 1)
            cookies[c_name] = c_val
        except ValueError:
            print("[!] Error: El formato de la cookie debe ser nombre=valor")
            return

    target_clean = args.target.replace("https://", "").replace("http://", "").replace("/", "_").strip("_")
    os.makedirs("reports", exist_ok=True)

    print(f"\n{'='*65}")
    print(f"[*] DarkScan v1.4.1 iniciando sobre: {args.target}")
    print(f"{'='*65}")
    
    # --- FASE 1: RECONOCIMIENTO (FINGERPRINTING) ---
    fp = Fingerprinter(args.target, "data/signatures/web_tech.json", cookies)
    results = await fp.analyze()

    if not results or (isinstance(results, list) and len(results) > 0 and "error" in results[0]):
        print(f"[!] Error: No se detectaron tecnologías o hubo un fallo de conexión.")
        return

    print("\n[+] Tecnologías Detectadas:")
    for res in results:
        print(f"    - {res['technology']:<12} [v{res['version']:<10}] [Confianza: {res['confidence']}]")
    
    # --- FASE 2: FUZZING DINÁMICO ---
    if args.fuzz or args.deep_fuzz:
        print("\n[*] FASE 2: Fuzzing Dinámico e Inteligente...")
        custom_path = args.deep_fuzz if args.deep_fuzz != "DEEP_MODE" else None
        is_deep = args.deep_fuzz == "DEEP_MODE"
        
        fuzzer = SmartFuzzer(args.target, results, cookies=cookies, custom_list=custom_path, deep_mode=is_deep)
        await fuzzer.run()
    else:
        print("\n[*] FASE 2: Fuzzing omitido.")

    # --- FASE 3: VULNERABILITY MAPPING (NIST Context) ---
    nist_context = []
    if args.nist and results:
        print("\n[*] FASE 3: Mapeo de Vulnerabilidades (NIST NVD)...")
        nist_key = args.nist if args.nist != "NO_KEY" else None
        mapper = VulnMapper(nist_key=nist_key, snyk_key=args.snyk)
        
        for res in results:
            tech, ver = res['technology'], res['version']
            if ver == "Unknown": continue
            
            vulns = await mapper.check_nist(tech, ver)
            if vulns:
                nist_context.extend(vulns)
                with open(f"reports/{target_clean}_nist.txt", "a", encoding="utf-8") as f:
                    f.writelines(vulns)
                print(f"    [+] {len(vulns)} potenciales vulnerabilidades encontradas para {tech}")

    # --- FASE 4: EXPLOIT VERIFIER (DYNAMIC & ADAPTIVE) ---
    print("\n[*] FASE 4: Validación Dinámica de Exploits (Safe-Checks)...")
    verifier = ExploitVerifier(args.target, cookies)
    
    # Se le pasa el contexto de NIST para que el fuzzing sea dirigido
    verified_vulns = await verifier.run_checks(results, nist_context=nist_context)
    
    if verified_vulns:
        print("\n    " + "!"*50)
        print("    [!!!] VULNERABILIDADES CONFIRMADAS POR DARKSCAN [!!!]")
        print("    " + "!"*50)
        for vuln in verified_vulns:
            severity = vuln.get('severity', 'UNKNOWN')
            cve = vuln.get('cve', 'N/A')
            print(f"    [ {severity} ] {vuln['tech']} -> {cve} ({vuln['type']})")
            print(f"               Ruta probada: {vuln['endpoint_tested']}")
    else:
        print("    [OK] No se confirmaron exploits en caliente.")

    print(f"\n{'='*65}")
    print("[*] Tarea finalizada con éxito.")

if __name__ == "__main__":
    try:
        # Volvemos al método estándar y compatible
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Escaneo abortado por el usuario.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Error inesperado durante la ejecución: {e}")
