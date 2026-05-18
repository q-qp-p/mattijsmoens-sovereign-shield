"""
SovereignShield OpenClaw Daemon
===============================
A lightweight FastAPI server that exposes SovereignShield's deterministic
InputFilter, CoreSafety, and optional VetoShield LLM semantic checks 
to the Node.js OpenClaw plugin via localhost.
"""

import json
import logging
import os
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Union

from sovereign_shield.input_filter import InputFilter
from sovereign_shield.core_safety import CoreSafety
from sovereign_shield.veto import VetoShield
from sovereign_shield.providers.openai_provider import OpenAIProvider
from sovereign_shield.providers.gemini import GeminiProvider
from sovereign_shield.providers.ollama import OllamaProvider

logger = logging.getLogger("ss_daemon")
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="SovereignShield OpenClaw Daemon")

# 1. Initialize Deterministic Layers
input_filter = InputFilter()

# 2. Initialize VetoShield (Optional Layer 6 Semantic Analysis)
veto_shield = None
provider_name = os.environ.get("VETO_PROVIDER", "").lower()

if provider_name == "openai" and os.environ.get("OPENAI_API_KEY"):
    logger.info("Initializing VetoShield with OpenAIProvider")
    veto_shield = VetoShield(OpenAIProvider(api_key=os.environ["OPENAI_API_KEY"]))
elif provider_name == "gemini" and os.environ.get("GEMINI_API_KEY"):
    logger.info("Initializing VetoShield with GeminiProvider")
    veto_shield = VetoShield(GeminiProvider(api_key=os.environ["GEMINI_API_KEY"]))
elif provider_name == "ollama":
    logger.info("Initializing VetoShield with OllamaProvider")
    model = os.environ.get("OLLAMA_MODEL", "llama3")
    veto_shield = VetoShield(OllamaProvider(model=model))
else:
    logger.info("VetoShield disabled (No VETO_PROVIDER set). Running pure deterministic mode.")

class ScanRequest(BaseModel):
    tool_name: str
    input: Union[str, Dict[str, Any]]

class ScanResponse(BaseModel):
    allowed: bool
    reason: str

@app.post("/scan", response_model=ScanResponse)
async def scan_endpoint(request: ScanRequest):
    try:
        tool_name = request.tool_name
        target_input = request.input

        # Pre-parse OpenClaw stringified JSON arguments to extract raw paths/commands
        parsed_args = target_input
        if isinstance(target_input, str):
            try:
                parsed_args = json.loads(target_input)
            except ValueError:
                pass

        # Layer 3: System-level OS constraints first
        if tool_name in ("bash", "system.run", "exec"):
            command_str = parsed_args.get("command", target_input) if isinstance(parsed_args, dict) else target_input
            allowed, reason = CoreSafety.audit_action("EXECUTE", str(command_str))
            if not allowed:
                return ScanResponse(allowed=False, reason=f"CoreSafety Blocked: {reason}")
        elif tool_name in ("fs_write", "fs_read"):
            # Basic file system check (e.g., stopping writes to /etc)
            path_arg = parsed_args.get("path", target_input) if isinstance(parsed_args, dict) else target_input
            allowed, reason = CoreSafety.audit_action("WRITE" if "write" in tool_name else "READ", str(path_arg))
            if not allowed:
                return ScanResponse(allowed=False, reason=f"CoreSafety Blocked: {reason}")
        
        # Layer 1/2/6: Structural and Semantic Analysis
        if veto_shield:
            # VetoShield automatically runs InputFilter and AdaptiveShield first
            result = veto_shield.scan(target_input)
            if not result["allowed"]:
                return ScanResponse(allowed=False, reason=f"VetoShield Blocked: {result.get('reason', 'Semantic attack detected')}")
        else:
            # Deterministic fallback mode (Sub-millisecond)
            is_safe, result_reason, _suspicion = input_filter.process(target_input)
            if not is_safe:
                return ScanResponse(allowed=False, reason=f"InputFilter Blocked: {result_reason}")
            
        return ScanResponse(allowed=True, reason="Safe")
        
    except Exception as e:
        logger.error(f"Error processing scan: {e}")
        return ScanResponse(allowed=False, reason=f"Error: {e}")

def start_server(port=8765):
    print(f"\n[SovereignShield Daemon] Active on http://127.0.0.1:{port}")
    if veto_shield:
        print("[SovereignShield Daemon] ✨ VetoShield Semantic Analysis ENABLED")
    else:
        print("[SovereignShield Daemon] ⚡ Deterministic Mode ONLY (Extreme speed)")
    print("Waiting for OpenClaw tool invocations...")
    uvicorn.run(app, host="127.0.0.1", port=port)

if __name__ == "__main__":
    start_server()
