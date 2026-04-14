import aiohttp
import asyncio
import os

class SmartFuzzer:
    def __init__(self, target, detected_techs, cookies=None, custom_list=None, deep_mode=False):
        self.target = target.rstrip('/')
        self.techs = [t['technology'].lower() for t in detected_techs]
        self.cookies = cookies or {}
        self.custom_list = custom_list
        self.deep_mode = deep_mode
        self.results = []
        self.wildcard_size = -1 # Para detectar falsos positivos
        
        # Mapeo de rutas CRÍTICAS por tecnología (Prioridad 1)
        self.critical_endpoints = {
            "grafana": ["metrics", "api/health", "api/admin/settings", "login", "api/v1/query"],
            "drupal": ["user/login", "CHANGELOG.txt", "cron.php", "xmlrpc.php", "sites/default/settings.php"],
            "nginx": ["nginx_status", "server-status"],
            "common": ["robots.txt", ".env", ".git/config", "admin", "backup", "v1/api"]
        }
        
        self.base_dirb = "/usr/share/wordlists/dirb"
        self.dirbuster_medium = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"

    async def _detect_wildcard(self, session):
        """Detecta si el servidor redirige todo a una página con tamaño constante."""
        random_path = "/detect_wildcard_random_12345"
        try:
            async with session.get(self.target + random_path, timeout=10, ssl=False, allow_redirects=False) as resp:
                self.wildcard_size = resp.content_length
                # Si el servidor no devuelve Content-Length, leemos el body para calcularlo
                if self.wildcard_size is None:
                    text = await resp.text()
                    self.wildcard_size = len(text)
        except:
            self.wildcard_size = -1

    async def fetch(self, session, path, report_file):
        url = f"{self.target}/{path.lstrip('/')}"
        try:
            async with session.get(url, timeout=7, ssl=False, allow_redirects=False) as resp:
                status = resp.status
                content = await resp.text()
                size = len(content)

                # Filtrado de Falsos Positivos:
                # Si el status es el mismo y el tamaño es idéntico al wildcard, lo ignoramos
                if size == self.wildcard_size and status in [301, 302, 200]:
                    return None

                res_data = {"path": path, "status": status, "size": size}
                
                # Escribir en el reporte (todas las respuestas)
                with open(report_file, "a", encoding="utf-8") as f:
                    f.write(f"[{status}] /{path} - Size: {size}\n")

                # Reportar por terminal solo 200, 403, 500
                if status in [200, 500]:
                    print(f"    [!] ENCONTRADO: {status} -> /{path} ({size} bytes)")
                
                return res_data
        except:
            return None

    async def run(self):
        # Preparar archivo de reporte
        target_name = self.target.split("//")[-1].replace("/", "_")
        report_file = f"reports/fuzz_{target_name}.txt"
        with open(report_file, "w") as f:
            f.write(f"Fuzzing Report for {self.target}\n{'='*40}\n")

        async with aiohttp.ClientSession(cookies=self.cookies) as session:
            # 0. Calibración
            await self._detect_wildcard(session)
            
            # 1. Definir rutas (Críticas + Wordlist)
            paths_to_test = []
            for tech in self.techs + ["common"]:
                paths_to_test.extend(self.critical_endpoints.get(tech, []))
            
            # Cargar Wordlist
            wordlist = self.custom_list if self.custom_list else (self.dirbuster_medium if self.deep_mode else f"{self.base_dirb}/common.txt")
            if os.path.exists(wordlist):
                with open(wordlist, 'r', errors='ignore') as f:
                    paths_to_test.extend([l.strip() for l in f if l.strip() and not l.startswith('#')])
            
            paths_to_test = list(dict.fromkeys(paths_to_test)) # Eliminar duplicados manteniendo orden
            
            print(f"[*] Calibración: Wildcard detectado (Size: {self.wildcard_size})")
            print(f"[*] Fuzzing iniciado. Resultados detallados en: {report_file}")

            semaphore = asyncio.Semaphore(50)
            async def sem_fetch(p):
                async with semaphore:
                    return await self.fetch(session, p, report_file)

            tasks = [sem_fetch(p) for p in paths_to_test]
            for f in asyncio.as_completed(tasks):
                res = await f
                if res: self.results.append(res)
        
        return self.results
