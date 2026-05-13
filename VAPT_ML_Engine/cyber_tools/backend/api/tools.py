"""
Tools metadata endpoint — returns the available tools and their GUI config schema.
The frontend uses this to dynamically render the Flag Cockpit panel for each tool.
"""
from fastapi import APIRouter
from backend.plugins.tools import TOOL_REGISTRY, NmapPlugin, GobusterPlugin, HydraPlugin, NucleiPlugin

router = APIRouter()

# This is the "schema" that tells the frontend how to render the GUI controls
TOOL_UI_CONFIG = {
    "nmap": {
        "name": "Nmap",
        "icon": "radar",
        "description": "Industry-standard port scanner with service/OS detection",
        "category": "Scanning",
        "controls": [
            {"id": "service_detection", "label": "Service Detection", "flag": "-sV", "type": "toggle", "default": True},
            {"id": "os_detection",      "label": "OS Detection",      "flag": "-O",  "type": "toggle", "default": False},
            {"id": "default_scripts",   "label": "Default Scripts",   "flag": "-sC", "type": "toggle", "default": False},
            {"id": "skip_host_discovery","label": "Skip Host Discovery","flag": "-Pn","type": "toggle", "default": False},
            {"id": "aggressive",        "label": "Aggressive Mode",   "flag": "-A",  "type": "toggle", "default": False},
            {"id": "all_ports",         "label": "All 65535 Ports",   "flag": "-p-", "type": "toggle", "default": False},
            {"id": "vuln_scripts",      "label": "Vuln Scripts",      "flag": "--script=vuln", "type": "toggle", "default": False},
            {"id": "http_enum",         "label": "HTTP Enum",         "flag": "--script=http-enum", "type": "toggle", "default": False},
            {"id": "smb_scripts",       "label": "SMB Scripts",       "flag": "--script=smb-*", "type": "toggle", "default": False},
            {"id": "timing",            "label": "Timing",            "flag": "-T",  "type": "slider", "min": 1, "max": 5, "default": 4},
            {"id": "ports",             "label": "Custom Ports",      "flag": "-p",  "type": "text",   "placeholder": "80,443,8080 or 1-1000"},
        ],
    },
    "gobuster": {
        "name": "Gobuster",
        "icon": "folder-search",
        "description": "Directory and DNS brute-forcing tool",
        "category": "Web",
        "controls": [
            {"id": "mode",              "label": "Mode",              "type": "select", "options": ["dir", "dns", "vhost"], "default": "dir"},
            {"id": "status_preset",     "label": "Status Codes",      "type": "select", "options": ["common", "all", "success_only"], "default": "common"},
            {"id": "wordlist",          "label": "Wordlist Path",     "type": "text",   "placeholder": "/path/to/wordlist.txt"},
            {"id": "extensions",        "label": "File Extensions",   "type": "text",   "placeholder": "php,html,js"},
            {"id": "threads",           "label": "Threads",           "type": "slider", "min": 5, "max": 100, "default": 10},
            {"id": "follow_redirects",  "label": "Follow Redirects",  "flag": "-r",     "type": "toggle", "default": False},
            {"id": "no_tls_validation", "label": "Skip TLS Verify",   "flag": "-k",     "type": "toggle", "default": False},
            {"id": "expanded_mode",     "label": "Expanded Output",   "flag": "-e",     "type": "toggle", "default": False},
        ],
    },
    "hydra": {
        "name": "Hydra",
        "icon": "key",
        "description": "Multi-protocol network credential brute-forcer",
        "category": "Auth",
        "controls": [
            {"id": "protocol",        "label": "Protocol",            "type": "select", "options": ["ssh","ftp","http-get","rdp","smb","telnet","mysql"], "default": "ssh"},
            {"id": "username",        "label": "Single Username",      "type": "text",   "placeholder": "admin"},
            {"id": "username_list",   "label": "Username Wordlist",    "type": "text",   "placeholder": "/path/to/users.txt"},
            {"id": "password",        "label": "Single Password",      "type": "text",   "placeholder": "password123"},
            {"id": "password_list",   "label": "Password Wordlist",    "type": "text",   "placeholder": "/path/to/rockyou.txt"},
            {"id": "port",            "label": "Custom Port",          "type": "number", "placeholder": "22"},
            {"id": "tasks",           "label": "Parallel Tasks",       "type": "slider", "min": 1, "max": 64, "default": 16},
            {"id": "stop_on_first",   "label": "Stop on First Match",  "flag": "-f",     "type": "toggle", "default": True},
            {"id": "verbose",         "label": "Verbose Output",       "flag": "-v",     "type": "toggle", "default": False},
        ],
    },
    "nuclei": {
        "name": "Nuclei",
        "icon": "bug",
        "description": "Template-based vulnerability scanner",
        "category": "Vulnerability",
        "controls": [
            {"id": "severities",        "label": "Severities",        "type": "multi-select", "options": ["info","low","medium","high","critical"], "default": ["medium","high","critical"]},
            {"id": "templates",         "label": "Template Path",      "type": "text",   "placeholder": "cves/ or /path/to/templates"},
            {"id": "tags",              "label": "Tags",               "type": "text",   "placeholder": "rce,sqli,xss"},
            {"id": "no_interactsh",     "label": "No OAST/Interactsh", "flag": "-no-interactsh", "type": "toggle", "default": False},
            {"id": "headless",          "label": "Headless Browser",   "flag": "-headless", "type": "toggle", "default": False},
        ],
    },
    "subfinder": {
        "name": "Subfinder",
        "icon": "globe",
        "description": "Passive subdomain discovery tool",
        "category": "Recon",
        "controls": [
            {"id": "recursive",  "label": "Recursive Discovery", "flag": "-recursive", "type": "toggle", "default": False},
            {"id": "silent",     "label": "Silent Mode",          "flag": "-silent",    "type": "toggle", "default": True},
        ],
    },
    "httpx": {
        "name": "httpx",
        "icon": "activity",
        "description": "Fast HTTP probing and tech detection",
        "category": "Web",
        "controls": [
            {"id": "title",             "label": "Page Title",         "flag": "-title",           "type": "toggle", "default": True},
            {"id": "tech_detect",       "label": "Tech Detection",     "flag": "-tech-detect",     "type": "toggle", "default": True},
            {"id": "status_code",       "label": "Status Code",        "flag": "-status-code",     "type": "toggle", "default": True},
            {"id": "follow_redirects",  "label": "Follow Redirects",   "flag": "-follow-redirects","type": "toggle", "default": True},
            {"id": "content_length",    "label": "Content Length",     "flag": "-content-length",  "type": "toggle", "default": False},
        ],
    },
}


@router.get("/")
async def list_tools():
    return {
        tool_id: {
            "id": tool_id,
            **TOOL_UI_CONFIG.get(tool_id, {"name": tool_id, "description": "", "category": "Other", "controls": []}),
        }
        for tool_id in TOOL_REGISTRY
    }


@router.get("/{tool_id}/config")
async def get_tool_config(tool_id: str):
    if tool_id not in TOOL_REGISTRY:
        from fastapi import HTTPException
        raise HTTPException(404, f"Tool '{tool_id}' not found")
    return TOOL_UI_CONFIG.get(tool_id, {"name": tool_id, "controls": []})
