import re
import aiohttp
import asyncio
import json

class Fingerprinter:
    def __init__(self, target, signatures_path, session_cookies=None):
        self.target = target.rstrip('/')
        self.signatures_path = signatures_path
        self.cookies = session_cookies or {}
        self.results = []
        self.detected_names = set()

    async def fetch(self, session, path="/"):
        # Cabeceras profesionales para evitar bloqueos por User-Agent (Drupal/WAF)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,webp,*/*;q=0.8",
            "Accept-Language": "es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        try:
            async with session.get(self.target + path, timeout=12, ssl=False, headers=headers) as resp:
                return await resp.text(), resp.headers, resp.status
        except Exception:
            return "", {}, 0

    async def analyze(self):
        try:
            with open(self.signatures_path, 'r', encoding='utf-8') as f:
                sigs = json.load(f)
        except Exception as e:
            return [{"error": f"Fallo al cargar firmas: {str(e)}"}]

        async with aiohttp.ClientSession(cookies=self.cookies) as session:
            body, headers, status = await self.fetch(session)
            
            if status == 0:
                return [{"error": "Objetivo inalcanzable (Timeout/DNS)."}]
            
            if status == 403:
                print("[!] Advertencia: Acceso Denegado (403). Intentando fingerprinting limitado...")

            # Unificar categorías para el escaneo
            all_sigs = sigs.get('frameworks', []) + sigs.get('servers', []) + sigs.get('libraries', [])
            await self._scan_layer(session, all_sigs, body, headers)
            
            return self.results

    async def _scan_layer(self, session, signatures, body, headers):
        for tech in signatures:
            if tech['name'] in self.detected_names: continue

            detected = False
            for check in tech.get('checks', []):
                if check['type'] == 'body' and check['value'] in body:
                    detected = True
                    break
                elif check['type'] == 'header' and check['key'] in headers:
                    if check['value'].lower() in headers[check['key']].lower():
                        detected = True
                        break

            if detected:
                self.detected_names.add(tech['name'])
                version, confidence = await self._verify_version_advanced(session, tech, body, headers)
                
                self.results.append({
                    "technology": tech['name'],
                    "version": version,
                    "confidence": f"{confidence * 100:.1f}%"
                })

    async def _verify_version_advanced(self, session, tech, body, headers):
        candidates = []

        # 1. Chequeos Agresivos (Confianza Máxima)
        for a_check in tech.get('aggressive_checks', []):
            v_body, _, v_status = await self.fetch(session, a_check['path'])
            if v_status == 200:
                match = re.search(a_check['regex'], v_body, re.I)
                if match:
                    candidates.append((match.group(1), 1.0))

        # 2. Chequeos Pasivos
        for v_check in tech.get('version_checks', []):
            source = body if v_check['location'] == 'body' else headers.get(v_check.get('key', 'Server'), "")
            match = re.search(v_check['regex'], source, re.I)
            if match:
                conf = v_check.get("confidence", 0.7)
                candidates.append((match.group(1), conf))

        if not candidates:
            return "Unknown", 0.5
        
        # Devolver el candidato con mayor confianza
        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates[0][0], candidates[0][1]
