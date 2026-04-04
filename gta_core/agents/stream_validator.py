import sys
import os
import asyncio

# Hard-coded linkage to CamXploit core
sys.path.append("/Users/michaelraftery/daproyect/camxploit")

try:
    # Attempting to import the specific Scanner class from your local camxploit tree
    from core.scanner import Scanner
    print("[GTA_AGENT] Successfully linked CamXploit Intelligence.")
except ImportError as e:
    print(f"[GTA_AGENT] Critical Linkage Failure: {e}")

async def validate_target(ip):
    # Wrapper for camxploit scanning
    return {"ip": ip, "status": "Ready for Scan"}
