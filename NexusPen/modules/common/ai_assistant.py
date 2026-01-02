#!/usr/bin/env python3
"""
NexusPen - AI Assistant Module
==============================
AI-powered vulnerability analysis, CVE research, and report generation.

Supports multiple AI providers via OpenRouter:
- DeepSeek (recommended)
- Claude
- GPT-4
- Mixtral
- And more...

Note: AI is used for UNDERSTANDING and ANALYSIS only, not for executing attacks.
"""

import os
import json
import requests
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

console = Console()


@dataclass
class AIConfig:
    """AI configuration."""
    api_key: str
    model: str = "deepseek/deepseek-r1-0528:free"
    base_url: str = "https://openrouter.ai/api/v1"
    temperature: float = 0.7
    max_tokens: int = 4096


class AIAssistant:
    """
    AI-powered assistant for penetration testing support.
    
    Uses AI for:
    - CVE analysis and explanation
    - Vulnerability research
    - Attack vector suggestions
    - Report writing
    - Remediation recommendations
    
    Does NOT:
    - Execute commands
    - Perform attacks
    - Access target systems
    """
    
    # Available models via OpenRouter
    MODELS = {
        'deepseek': 'deepseek/deepseek-r1-0528:free',  # Free & powerful!
        'deepseek-chat': 'deepseek/deepseek-chat',
        'deepseek-coder': 'deepseek/deepseek-coder',
        'claude-3': 'anthropic/claude-3-haiku',
        'claude-sonnet': 'anthropic/claude-3.5-sonnet',
        'gpt-4': 'openai/gpt-4-turbo',
        'gpt-4o': 'openai/gpt-4o',
        'mixtral': 'mistralai/mixtral-8x7b-instruct',
        'llama-70b': 'meta-llama/llama-3-70b-instruct',
    }
    
    SYSTEM_PROMPT = """You are a cybersecurity expert assistant for penetration testing analysis.

Your role is to:
1. Explain vulnerabilities and CVEs in detail
2. Describe how vulnerabilities work technically
3. Suggest testing methodologies (NOT execute them)
4. Help write professional security reports
5. Provide remediation recommendations

You provide EDUCATIONAL and ANALYTICAL support only.
You help security professionals understand vulnerabilities for authorized testing.
You do NOT provide step-by-step exploitation instructions or malicious code.

Always be precise, technical, and helpful for legitimate security research."""

    def __init__(self, api_key: str = None, model: str = 'deepseek'):
        """
        Initialize AI Assistant.
        
        Args:
            api_key: OpenRouter API key (or set OPENROUTER_API_KEY env var)
            model: Model to use (deepseek, claude-3, gpt-4, etc.)
        """
        self.api_key = api_key or os.getenv('OPENROUTER_API_KEY')
        self.model = self.MODELS.get(model, 'deepseek/deepseek-r1-0528:free')
        self.base_url = "https://openrouter.ai/api/v1"
        self.conversation_history = []
        
        if not self.api_key:
            console.print("[yellow]⚠️ No API key provided. Set OPENROUTER_API_KEY or pass api_key parameter.[/yellow]")
    
    def _make_request(self, messages: List[Dict], temperature: float = 0.7) -> Optional[str]:
        """Make API request to OpenRouter."""
        if not self.api_key:
            console.print("[red]❌ API key required. Get one from https://openrouter.ai/keys[/red]")
            return None
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/nexuspen",
            "X-Title": "NexusPen Security Framework"
        }
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": 4096
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=60
            )
            
            if response.status_code == 200:
                data = response.json()
                return data['choices'][0]['message']['content']
            else:
                console.print(f"[red]API Error: {response.status_code} - {response.text}[/red]")
                return None
                
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Network error: {e}[/red]")
            return None
    
    def analyze_cve(self, cve_id: str, cve_data: Dict = None) -> Optional[str]:
        """
        Analyze and explain a CVE in detail.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)
            cve_data: Optional CVE data from Shodan CVEDB
        """
        console.print(f"\n[cyan]🤖 AI analyzing {cve_id}...[/cyan]")
        
        context = f"CVE ID: {cve_id}"
        if cve_data:
            context += f"""
Summary: {cve_data.get('summary', 'N/A')}
CVSS Score: {cve_data.get('cvss', 'N/A')}
CVSS v3: {cve_data.get('cvss_v3', 'N/A')}
EPSS: {cve_data.get('epss', 'N/A')}
KEV (Known Exploited): {cve_data.get('kev', False)}
Affected Products (CPEs): {', '.join(cve_data.get('cpes', [])[:5])}
"""
        
        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "user", "content": f"""Analyze this vulnerability in detail:

{context}

Please provide:
1. **Vulnerability Overview**: What is this vulnerability?
2. **Technical Details**: How does it work technically?
3. **Attack Vector**: What are the possible attack scenarios?
4. **Impact Assessment**: What can an attacker achieve?
5. **Detection Methods**: How can this be detected in an environment?
6. **Mitigation/Remediation**: How to fix or mitigate this vulnerability?
7. **Testing Approach**: What methodology should be used to test for this vulnerability in an authorized assessment?

Be technical and detailed."""}
        ]
        
        response = self._make_request(messages, temperature=0.5)
        
        if response:
            console.print(Panel(Markdown(response), title=f"🤖 AI Analysis: {cve_id}", 
                               border_style="cyan"))
        
        return response
    
    def suggest_exploits_for_service(self, service: str, version: str = None) -> Optional[str]:
        """
        Suggest testing approach for a specific service.
        
        Args:
            service: Service name
            version: Service version
        """
        console.print(f"\n[cyan]🤖 AI researching {service} {version or ''}...[/cyan]")
        
        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "user", "content": f"""I'm conducting an authorized penetration test and discovered this service:

Service: {service}
Version: {version or 'Unknown'}

Please provide:
1. **Known Vulnerabilities**: What CVEs affect this version?
2. **Common Misconfigurations**: What misconfigurations should I check?
3. **Testing Methodology**: How should I test this service?
4. **Tools Suggestion**: What tools are commonly used (nmap scripts, metasploit modules, etc.)?
5. **Attack Surface**: What are the potential attack vectors?

Focus on the testing methodology and what to look for during an authorized assessment."""}
        ]
        
        response = self._make_request(messages, temperature=0.6)
        
        if response:
            console.print(Panel(Markdown(response), title=f"🤖 AI Research: {service}", 
                               border_style="green"))
        
        return response
    
    def explain_vulnerability(self, vuln_type: str) -> Optional[str]:
        """
        Explain a vulnerability type in detail.
        
        Args:
            vuln_type: Vulnerability type (e.g., "SQL Injection", "Buffer Overflow")
        """
        console.print(f"\n[cyan]🤖 AI explaining {vuln_type}...[/cyan]")
        
        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "user", "content": f"""Explain this vulnerability type in detail for a penetration tester:

Vulnerability Type: {vuln_type}

Cover:
1. What is it and how does it work?
2. Common causes and conditions
3. Real-world examples (CVEs)
4. Detection/testing methodology
5. Impact and severity
6. Remediation best practices

Be technical and comprehensive."""}
        ]
        
        response = self._make_request(messages, temperature=0.5)
        
        if response:
            console.print(Panel(Markdown(response), title=f"🤖 Vulnerability Explained: {vuln_type}", 
                               border_style="yellow"))
        
        return response
    
    def generate_report_section(self, finding: Dict) -> Optional[str]:
        """
        Generate a professional report section for a finding.
        
        Args:
            finding: Dict with 'title', 'severity', 'description', 'evidence', 'affected'
        """
        console.print("\n[cyan]🤖 AI generating report section...[/cyan]")
        
        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "user", "content": f"""Generate a professional penetration testing report section for this finding:

Title: {finding.get('title', 'Unknown')}
Severity: {finding.get('severity', 'Unknown')}
Description: {finding.get('description', '')}
Evidence: {finding.get('evidence', '')}
Affected Systems: {finding.get('affected', '')}

Format it as a professional security report with:
1. Finding Title
2. Severity Rating
3. CVSS Score (if applicable)
4. Description
5. Technical Details
6. Evidence/Proof of Concept
7. Impact
8. Remediation Recommendations
9. References

Use professional language suitable for executive and technical audiences."""}
        ]
        
        response = self._make_request(messages, temperature=0.4)
        
        if response:
            console.print(Panel(Markdown(response), title="🤖 AI Report Section", 
                               border_style="magenta"))
        
        return response
    
    def analyze_scan_results(self, results: Dict) -> Optional[str]:
        """
        Analyze scan results and provide insights.
        
        Args:
            results: Scan results dictionary
        """
        console.print("\n[cyan]🤖 AI analyzing scan results...[/cyan]")
        
        results_summary = json.dumps(results, indent=2, default=str)[:2000]  # Limit size
        
        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "user", "content": f"""Analyze these penetration testing scan results and provide insights:

```json
{results_summary}
```

Please provide:
1. **Summary**: Overview of what was found
2. **Critical Findings**: Most important findings that need immediate attention
3. **Risk Assessment**: Overall risk level
4. **Attack Paths**: Potential attack paths based on findings
5. **Prioritization**: What to focus on first
6. **Next Steps**: Recommended next steps in the assessment

Be concise but thorough."""}
        ]
        
        response = self._make_request(messages, temperature=0.5)
        
        if response:
            console.print(Panel(Markdown(response), title="🤖 AI Scan Analysis", 
                               border_style="blue"))
        
        return response
    
    def chat(self, message: str) -> Optional[str]:
        """
        Interactive chat for general security questions.
        
        Args:
            message: User's question/message
        """
        self.conversation_history.append({"role": "user", "content": message})
        
        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT}
        ] + self.conversation_history[-10:]  # Keep last 10 messages
        
        response = self._make_request(messages, temperature=0.7)
        
        if response:
            self.conversation_history.append({"role": "assistant", "content": response})
            console.print(Panel(Markdown(response), title="🤖 AI Assistant", 
                               border_style="cyan"))
        
        return response
    
    def map_cve_to_exploit(self, cve_id: str, cve_data: Dict = None) -> Optional[Dict]:
        """
        Use AI to suggest Metasploit modules or exploit approaches for a CVE.
        
        Args:
            cve_id: CVE identifier
            cve_data: Optional CVE data
        """
        console.print(f"\n[cyan]🤖 AI mapping {cve_id} to exploit approaches...[/cyan]")
        
        context = f"CVE: {cve_id}"
        if cve_data:
            context += f"\nSummary: {cve_data.get('summary', '')}"
            context += f"\nAffected: {', '.join(cve_data.get('cpes', [])[:5])}"
        
        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "user", "content": f"""For the following vulnerability, provide exploitation research information:

{context}

Please provide in JSON format:
{{
    "metasploit_modules": ["list of potential Metasploit module paths"],
    "nuclei_templates": ["list of relevant Nuclei template names"],
    "nmap_scripts": ["list of relevant Nmap NSE scripts"],
    "manual_testing": "Brief description of manual testing approach",
    "tools": ["list of other relevant tools"],
    "exploitdb_keywords": ["keywords to search in ExploitDB"]
}}

Only include options that are likely to exist and be relevant. If unsure, leave empty."""}
        ]
        
        response = self._make_request(messages, temperature=0.3)
        
        if response:
            # Try to parse JSON from response
            try:
                # Find JSON in response
                import re
                json_match = re.search(r'\{[\s\S]*\}', response)
                if json_match:
                    result = json.loads(json_match.group())
                    console.print("[green]✓ AI mapping complete[/green]")
                    return result
            except json.JSONDecodeError:
                pass
            
            console.print(Panel(Markdown(response), title=f"🤖 Exploit Research: {cve_id}"))
        
        return None
    
    def generate_executive_summary(self, findings: List[Dict]) -> Optional[str]:
        """
        Generate an executive summary for a penetration test report.
        
        Args:
            findings: List of findings dictionaries
        """
        console.print("\n[cyan]🤖 AI generating executive summary...[/cyan]")
        
        findings_summary = json.dumps(findings[:20], indent=2, default=str)[:3000]
        
        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "user", "content": f"""Generate a professional executive summary for a penetration testing report based on these findings:

```json
{findings_summary}
```

The executive summary should:
1. Be suitable for non-technical stakeholders
2. Highlight the most critical risks
3. Provide an overall security posture assessment
4. Include key recommendations
5. Be approximately 300-500 words
6. Use professional language

Format it as markdown."""}
        ]
        
        response = self._make_request(messages, temperature=0.4)
        
        if response:
            console.print(Panel(Markdown(response), title="🤖 Executive Summary", 
                               border_style="magenta"))
        
        return response


class CVEResearcher:
    """
    AI-powered CVE research assistant.
    Combines Shodan CVEDB with AI analysis.
    """
    
    def __init__(self, api_key: str = None, model: str = 'deepseek'):
        self.ai = AIAssistant(api_key, model)
        
        # Import Shodan CVEDB
        try:
            from .cve_intel import ShodanCVEDB
            self.cvedb = ShodanCVEDB()
            self.cvedb_available = True
        except ImportError:
            self.cvedb = None
            self.cvedb_available = False
    
    def research_cve(self, cve_id: str) -> Dict:
        """
        Full CVE research: fetch data from Shodan and analyze with AI.
        
        Args:
            cve_id: CVE identifier
        """
        console.print(f"\n[bold cyan]═══ CVE Research: {cve_id} ═══[/bold cyan]")
        
        result = {
            'cve_id': cve_id,
            'shodan_data': None,
            'ai_analysis': None,
            'exploit_mapping': None
        }
        
        # 1. Fetch from Shodan CVEDB
        if self.cvedb_available:
            console.print("\n[cyan]📡 Phase 1: Fetching CVE data from Shodan...[/cyan]")
            cve_data = self.cvedb.get_cve(cve_id)
            if cve_data:
                result['shodan_data'] = {
                    'summary': cve_data.summary,
                    'cvss': cve_data.cvss,
                    'cvss_v3': cve_data.cvss_v3,
                    'epss': cve_data.epss,
                    'kev': cve_data.kev,
                    'cpes': cve_data.cpes,
                    'references': cve_data.references
                }
        
        # 2. AI Analysis
        console.print("\n[cyan]🤖 Phase 2: AI Analysis...[/cyan]")
        result['ai_analysis'] = self.ai.analyze_cve(cve_id, result['shodan_data'])
        
        # 3. Exploit Mapping
        console.print("\n[cyan]🎯 Phase 3: Exploit Research...[/cyan]")
        result['exploit_mapping'] = self.ai.map_cve_to_exploit(cve_id, result['shodan_data'])
        
        return result
    
    def research_service(self, service: str, version: str = None) -> Dict:
        """
        Research vulnerabilities for a service using AI.
        
        Args:
            service: Service name
            version: Service version
        """
        console.print(f"\n[bold cyan]═══ Service Research: {service} {version or ''} ═══[/bold cyan]")
        
        result = {
            'service': service,
            'version': version,
            'known_cves': [],
            'ai_analysis': None
        }
        
        # 1. Search CVEs from Shodan
        if self.cvedb_available:
            console.print("\n[cyan]📡 Searching known CVEs...[/cyan]")
            cves = self.cvedb.get_cves_by_product(service)
            
            # Filter by version if provided
            if version and cves:
                # Keep top CVEs
                result['known_cves'] = [
                    {'cve': c.cve_id, 'cvss': c.cvss, 'kev': c.kev}
                    for c in sorted(cves, key=lambda x: x.cvss, reverse=True)[:10]
                ]
        
        # 2. AI Analysis
        console.print("\n[cyan]🤖 AI Research...[/cyan]")
        result['ai_analysis'] = self.ai.suggest_exploits_for_service(service, version)
        
        return result


# Helper functions
def setup_ai(api_key: str = None, model: str = 'deepseek') -> AIAssistant:
    """Quick setup for AI assistant."""
    return AIAssistant(api_key, model)


def research_cve(cve_id: str, api_key: str = None) -> Dict:
    """Quick CVE research."""
    researcher = CVEResearcher(api_key)
    return researcher.research_cve(cve_id)
