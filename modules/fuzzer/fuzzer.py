import asyncio
import aiohttp
import sys

class SmartFuzzer:
    def __init__(self, target, technologies, session_cookies=None):
        self.target = target.rstrip('/')
        self.techs = [t['technology'].lower() for t in technologies]
        self.cookies = session_cookies or {}
        
        # Diccionario de endpoints críticos por tecnología
        self.wordlists = {
            "grafana": [
                "/api/health", "/api/admin/settings", "/api/users", 
                "/metrics", "/api/dashboards/home", "/api/org"
            ],
            "nginx": [
                "/nginx_status", "/.nginx/config"
            ],
            "wordpress": [
                "/wp-json/wp/v2/users", "/wp-login.php", 
                "/wp-config.php.bak", "/xmlrpc.php", "/wp-content/debug.log"
            ],
            "django": [
                "/admin/login/", "/api-auth/login/", "/__debug__/", 
                "/static/admin/", "/manage.py"
            ],
            "drupal": [
                "/user/login", "/CHANGELOG.txt", "/core/install.php", 
                "/web.config", "/sites/default/settings.php"
            ],
            "common": [
                "/.git/config", "/.env", "/robots.txt", "/backup.sql", 
                "/.ssh/id_rsa", "/server-status", "/phpinfo.php"
            ]
        }

    async def test_endpoint(self, session, path):
        url = f"{self.target}{path}"
        try:
            # Usamos allow_redirects=False para detectar paneles de login sin entrar
            async with session.get(url, timeout=5, allow_redirects=False, ssl=False) as response:
                status = response.status
                size = response.content_length or 0
                
                # Clasificamos resultados interesantes
                if status == 200:
                    return {"path": path, "status": status, "size": size, "note": "ACCESIBLE"}
                elif status == 301 or status == 302:
                    return {"path": path, "status": status, "size": size, "note": f"REDIRECT -> {response.headers.get('Location')}"}
                elif status == 403:
                    return {"path": path, "status": status, "size": size, "note": "PROHIBIDO (Interesante)"}
                
        except Exception:
            pass
        return None

    async def run(self):
        # Empezamos con la lista común
        paths_to_test = set(self.wordlists["common"])
        
        # Añadimos rutas específicas según la tecnología detectada
        detected_any = False
        for tech in self.techs:
            if tech in self.wordlists:
                paths_to_test.update(self.wordlists[tech])
                detected_any = True

        if not detected_any:
            print("[!] No hay wordlists específicas para las tecnologías detectadas. Usando 'common'.")

        print(f"[*] Iniciando Fuzzing asíncrono sobre {len(paths_to_test)} rutas...")
        
        results = []
        # Limitamos las conexiones simultáneas para no tumbar el sitio (TCP Semaphore)
        connector = aiohttp.TCPConnector(limit=10) 
        async with aiohttp.ClientSession(cookies=self.cookies, connector=connector) as session:
            tasks = [self.test_endpoint(session, path) for path in paths_to_test]
            fuzz_results = await asyncio.gather(*tasks)
            
            # Filtrar los None (404s y errores)
            results = [r for r in fuzz_results if r]
            
        return results
