import aiohttp
import json
import re
import asyncio

class Fingerprinter:
    def __init__(self, target, signatures_path, session_cookies=None):
        if not target.startswith(('http://', 'https://')):
            self.target = f"https://{target.rstrip('/')}"
        else:
            self.target = target.rstrip('/')
            
        self.signatures_path = signatures_path
        self.cookies = session_cookies or {}
        self.results = []

    def load_signatures(self):
        try:
            with open(self.signatures_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            return []

    async def analyze(self):
        signatures = self.load_signatures()
        # Priorizar firmas específicas
        signatures = sorted(signatures, key=lambda x: x.get('priority', 10))
        
        headers = {"User-Agent": "DarkScan/1.2 (WhatWeb-Inspired)"}
        
        async with aiohttp.ClientSession(cookies=self.cookies, headers=headers) as session:
            try:
                # PASO 1: Análisis del Index
                async with session.get(self.target, timeout=10, ssl=False) as response:
                    body = await response.text()
                    resp_headers = response.headers
                    
                    for tech in signatures:
                        match_count = 0
                        is_match = False
                        
                        # Verificación de firmas
                        for check in tech['checks']:
                            if check['type'] == 'header' and check.get('key') in resp_headers:
                                if check['value'].lower() in resp_headers[check['key']].lower():
                                    match_count += 1
                                    is_match = True
                            elif check['type'] == 'body' and check['value'] in body:
                                match_count += 1
                                is_match = True

                        if is_match:
                            version = "Unknown"
                            
                            # Intentar extraer versión con Regex mejorada
                            if "version_regex" in tech:
                                v_match = re.search(tech['version_regex'], body, re.IGNORECASE)
                                if v_match:
                                    version = v_match.group(1) if v_match.groups() else v_match.group(0)

                            # PASO 2: Lógica de Re-intento Activo (Tipo WhatWeb)
                            # Si detectamos Grafana pero la versión es dudosa o no está, consultamos API
                            if tech['name'] == "Grafana" and (version == "Unknown" or version == "1.0.0"):
                                try:
                                    async with session.get(f"{self.target}/api/health", timeout=5) as v_resp:
                                        if v_resp.status == 200:
                                            v_data = await v_resp.json()
                                            if 'version' in v_data:
                                                version = v_data['version']
                                except:
                                    pass # Si el API falla, nos quedamos con lo que tenemos

                            # Fallback para servidores web (Nginx/Apache) vía Header
                            if version == "Unknown" and "Server" in resp_headers:
                                s_match = re.search(r'/([0-9\.]+)', resp_headers['Server'])
                                if s_match: version = s_match.group(1)

                            self.results.append({
                                "technology": tech['name'],
                                "version": version,
                                "confidence": f"{(match_count / len(tech['checks'])) * 100:.1f}%"
                            })
                            
                return self.results

            except Exception as e:
                return [{"error": f"Fallo de conexión: {str(e)}"}]
