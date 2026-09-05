import os
from typing import Optional, Dict, Any
from openai import OpenAI

DEFAULT_GATEWAY_URL = "http://localhost:14141/v1"

class IronWarden(OpenAI):
    """
    Drop-in OpenAI client configured to route traffic through the IronWarden
    Sovereign AI Privacy & Security Gateway.
    """
    def __init__(
        self,
        api_key: Optional[str] = None,
        gateway_url: Optional[str] = None,
        upstream_key: Optional[str] = None,
        target_url: Optional[str] = None,
        auth_token: Optional[str] = None,
        default_headers: Optional[Dict[str, str]] = None,
        **kwargs: Any
    ):
        base_url = gateway_url or os.environ.get("IRONWARDEN_GATEWAY_URL", DEFAULT_GATEWAY_URL)
        resolved_api_key = api_key or os.environ.get("OPENAI_API_KEY", "sk-ironwarden-default")
        
        headers = default_headers.copy() if default_headers else {}
        
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        elif "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {resolved_api_key}"
            
        if upstream_key:
            headers["X-IronWarden-Upstream-Key"] = upstream_key
            
        if target_url:
            headers["X-IronWarden-Target-URL"] = target_url

        super().__init__(
            api_key=resolved_api_key,
            base_url=base_url,
            default_headers=headers,
            **kwargs
        )
