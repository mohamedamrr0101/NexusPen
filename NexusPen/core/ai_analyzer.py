import os
import json
from typing import List, Dict, Optional
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

console = Console()

class AIAnalyzer:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        self.client = None
        self.enabled = False
        
        if self.api_key:
            self._init_client()
            
    def _init_client(self):
        if not OpenAI:
            console.print("[yellow]⚠ OpenAI module not found. Install with: pip install openai[/yellow]")
            return
            
        try:
            self.client = OpenAI(
                api_key=self.api_key,
                base_url="https://openrouter.ai/api/v1",
                default_headers={
                    "HTTP-Referer": "https://github.com/mohamedamrr0101/NexusPen",
                    "X-Title": "NexusPen",
                }
            )
            self.enabled = True
            console.print("[green]🧠 OpenRouter (DeepSeek) Initialized[/green]")
        except Exception as e:
            console.print(f"[red]❌ Failed to initialize OpenRouter: {e}[/red]")

    def summarize_phase(self, phase_name: str, command_history: List[Dict], findings: List[Dict]) -> None:
        if not self.enabled or not self.client:
            return

        console.print(f"\n[bold cyan]🧠 Analyzing {phase_name} results with DeepSeek AI...[/bold cyan]")
        
        # Prepare context for AI
        commands_summary = []
        for cmd in command_history:
            # simple truncation for very large updates
            output_snippet = cmd.get('stdout', '')[:500] if cmd.get('stdout') else "No output"
            commands_summary.append(f"Command: {' '.join(cmd['command'])}\nOutput Snippet:\n{output_snippet}\nSuccess: {cmd['status'] == 'SUCCESS'}\n")
            
        findings_summary = [f"- {f.get('title')}: {f.get('description')} ({f.get('severity')})" for f in findings]
        
        prompt = f"""
You are a senior penetration tester assisting with a security assessment. 
Analyze the following execution log for the '{phase_name}' phase.

COMMANDS EXECUTED:
{chr(10).join(commands_summary)}

FINDINGS DETECTED:
{chr(10).join(findings_summary) if findings_summary else "No specific findings recorded by tools yet."}

TASK:
Provide a concise, professional summary of this phase.
1. Highlight what was discovered (open ports, services, interesting headers, vulnerabilities).
2. Point out any executed commands that failed or timed out and might need retrying.
3. Suggest 1-2 immediate next steps based on these specific results.
4. Format the output clearly using Markdown (headers, bullet points).
5. Be direct and technical.
"""

        try:
            response = self.client.chat.completions.create(
                model="deepseek/deepseek-chat",
                messages=[
                    {"role": "system", "content": "You are an elite penetration tester providing concise, actionable tactical analysis."},
                    {"role": "user", "content": prompt}
                ],
                stream=False
            )
            
            analysis = response.choices[0].message.content
            
            console.print(Panel(
                Markdown(analysis),
                title=f"🧠 DeepSeek Analysis - {phase_name}",
                border_style="cyan"
            ))
            
        except Exception as e:
            console.print(f"[red]❌ AI Analysis failed: {e}[/red]")
