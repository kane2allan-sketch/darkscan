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
    parser = argparse.ArgumentParser(description="DarkScan - Professional Pentesting Framework v1.4")
    parser.add_argument("-t", "--target", help="URL objetivo", required=True)
    parser.add_argument("-c", "--cookie", help="Cookie de sesión (nombre=valor)", default=None)
    parser.add_argument("--nist", help="Activar NIST NVD", nargs='?', const="NO_KEY")
    parser.add_argument("--snyk", help="Activar Snyk (Token)", default=None)
    
    # Parámetros de Fuzzing Actualizados
    parser.add_argument("-f", "--fuzz", help="Ejecutar fuzzing inteligente (Wordlists cortas)", action="store_true")
    parser.add_argument("-df", "--deep-fuzz", help="Deep Fuzz (Medium list) o ruta a lista personalizada", 
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
    print(f"[*] DarkScan v1.4 iniciando sobre: {args.target}")
    print(f"{'='*65}")
    
    # --- FASE 1: RECONOCIMIENTO ---
    fp = Fingerprinter(args.target, "data/signatures/web_tech.json", cookies)
    results = await fp.analyze()

    # Validación robusta de resultados para evitar IndexError
    if results is None:
        print("[!] Error Crítico: El motor de análisis no devolvió datos.")
        return
        
    if isinstance(results, list) and len(results) > 0 and "error" in results[0]:
        print(f"[!] Error: {results[0].get('error', 'Fallo de conexión.')}")
        return

    if not results:
        print("[?] No se detectaron tecnologías conocidas mediante fingerprinting.")
    else:
        print("\n[+] Tecnologías Detectadas:")
        for res in results:
            print(f"    - {res['technology']:<12} [v{res['version']:<10}] [Confianza: {res['confidence']}]")
    
    # --- FASE 2: FUZZING DINÁMICO ---
    fuzz_matches = []
    if args.fuzz or args.deep_fuzz:
        print("\n[*] FASE 2: Fuzzing Dinámico e Inteligente...")
        
        custom_path = None
        is_deep = False
        
        if args.deep_fuzz:
            if args.deep_fuzz == "DEEP_MODE":
                is_deep = True
            else:
                custom_path = args.deep_fuzz # El usuario pasó una ruta personalizada
        
        fuzzer = SmartFuzzer(
            args.target, 
            results, 
            cookies=cookies, 
            custom_list=custom_path, 
            deep_mode=is_deep
        )
        fuzz_matches = await fuzzer.run()
    else:
        print("\n[*] FASE 2: Fuzzing omitido (use -f o -df para activar).")

    # --- FASE 3: EXPLOIT VERIFIER ---
    print("\n[*] FASE 3: Validación de Exploits Críticos (Safe-Checks)...")
    verifier = ExploitVerifier(args.target, cookies)
    verified_vulns = await verifier.run_checks(results)
    
    if verified_vulns:
        print("\n    [!!!] VULNERABILIDADES CONFIRMADAS [!!!]")
        for vuln in verified_vulns:
            print(f"    [ {vuln['severity']} ] {vuln['tech']} -> {vuln['cve']} ({vuln['type']})")
            print(f"           Ruta: {vuln['endpoint_tested']}")
    else:
        print("    [OK] No se confirmaron exploits críticos.")

    # --- FASE 4: VULNERABILITY MAPPING ---
    if (args.nist or args.snyk) and results:
        nist_key = args.nist if args.nist != "NO_KEY" else None
        mapper = VulnMapper(nist_key=nist_key, snyk_key=args.snyk)
        
        for res in results:
            tech, ver = res['technology'], res['version']
            if ver == "Unknown": continue
            
            if args.nist:
                nist_vulns = await mapper.check_nist(tech, ver)
                if nist_vulns:
                    with open(f"reports/{target_clean}_nist.txt", "a", encoding="utf-8") as f:
                        f.writelines(nist_vulns)
                    print(f"    [+] Reporte NIST generado para {tech}")

    print(f"\n{'='*65}")
    print("[*] Tarea finalizada.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Escaneo abortado por el usuario.")
        sys.exit(0)
