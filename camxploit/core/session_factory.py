"""
Secure HTTP session management for GRIDLAND plugins.

Provides centralized session factory with standardized evasion tactics.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import aiohttp
import random
import yaml
from pathlib import Path
from ..utils.validation import validate_url

@dataclass
class SessionConfig:
    """Configuration for secure HTTP sessions"""
    proxy: Optional[str] = None
    user_agent_pool: List[str] = field(default_factory=list)
    timeout: float = 30.0
    verify_ssl: bool = False
    max_redirects: int = 3
    rate_limit: float = 1.0  # requests per second
    retry_attempts: int = 3
    retry_backoff: float = 1.0

class SessionManager:
    """Centralized secure HTTP session manager"""

    # Default user agents simulating modern browsers
    DEFAULT_USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0"
    ]

    @classmethod
    def load_config(cls) -> SessionConfig:
        """Load session configuration from YAML file"""
        config_path = Path(__file__).parent.parent.parent / 'data' / 'config' / 'session.yaml'
        
        try:
            if config_path.exists():
                with open(config_path) as f:
                    config = yaml.safe_load(f)
                    return SessionConfig(
                        proxy=config.get('proxies', {}).get('pool', [None])[0],
                        user_agent_pool=config.get('evasion', {}).get('user_agents', cls.DEFAULT_USER_AGENTS),
                        timeout=config.get('session', {}).get('default_timeout', 30.0),
                        verify_ssl=config.get('session', {}).get('verify_ssl', False),
                        max_redirects=config.get('session', {}).get('max_redirects', 3),
                        rate_limit=config.get('session', {}).get('rate_limit', 1.0)
                    )
        except Exception:
            pass
            
        # Return defaults if config loading fails
        return SessionConfig(user_agent_pool=cls.DEFAULT_USER_AGENTS)

    @classmethod
    def _get_secure_headers(cls, config: SessionConfig) -> Dict[str, str]:
        """Generate secure, randomized request headers"""
        user_agent = random.choice(config.user_agent_pool)
        
        headers = {
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache'
        }
        
        # Randomize header order
        headers_list = list(headers.items())
        random.shuffle(headers_list)
        return dict(headers_list)

    @classmethod
    async def create_secure_session(
        cls,
        config: Optional[SessionConfig] = None
    ) -> aiohttp.ClientSession:
        """
        Create secure, evasion-enabled HTTP session.
        
        Args:
            config: Optional session configuration

        Returns:
            aiohttp.ClientSession: Configured client session
        """
        if config is None:
            config = cls.load_config()
            
        # Generate randomized secure headers
        headers = cls._get_secure_headers(config)
        
        # Configure proxy settings if enabled
        proxy = config.proxy
        if proxy and not proxy.startswith(('http://', 'https://', 'socks5://')):
            proxy = f'http://{proxy}'

        # Create secure session with evasion settings        
        session = aiohttp.ClientSession(
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=config.timeout),
            trust_env=True,  # Allow environment proxy settings
            skip_auto_headers=['User-Agent'],  # We handle User-Agent manually
            raise_for_status=True
        )
        
        if proxy:
            session._proxy = proxy
            session._proxy_auth = None
            
        return session

    @classmethod
    async def secure_request(
        cls,
        url: str,
        method: str = 'GET',
        config: Optional[SessionConfig] = None,
        **kwargs
    ) -> aiohttp.ClientResponse:
        """
        Perform secure HTTP request with evasion tactics.

        Args:
            url: Target URL
            method: HTTP method to use
            config: Optional session configuration
            **kwargs: Additional request parameters

        Returns:
            aiohttp.ClientResponse: Response from request
        """
        if config is None:
            config = cls.load_config()
            
        # Validate URL
        validate_url(url)
        
        session = await cls.create_secure_session(config)
        async with session:
            response = await session.request(method, url, **kwargs)
            return response