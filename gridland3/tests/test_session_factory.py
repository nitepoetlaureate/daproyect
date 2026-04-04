"""
Test suite for the secure session factory.
"""

import pytest
import aiohttp
from unittest.mock import patch, MagicMock, AsyncMock
from camxploit.core.session_factory import SessionManager, SessionConfig
from camxploit.core.exceptions import ValidationError
from pathlib import Path
import yaml

pytest_plugins = ['asyncio']

@pytest.fixture
def mock_session():
    """Mock aiohttp ClientSession"""
    session = MagicMock(spec=aiohttp.ClientSession)
    session._default_headers = {
        'User-Agent': 'Test Agent',
        'Connection': 'close'
    }
    session._timeout = aiohttp.ClientTimeout(total=30.0)
    
    # Make session awaitable
    async def mock_aenter():
        return session
    async def mock_aexit(*args):
        pass
    async def mock_request(*args, **kwargs):
        response = MagicMock()
        response.status = 200
        response.headers = {'content-type': 'text/html'}
        return response
        
    session.__aenter__ = AsyncMock(side_effect=mock_aenter)
    session.__aexit__ = AsyncMock(side_effect=mock_aexit)
    session.request = AsyncMock(side_effect=mock_request)
    
    return session

@pytest.fixture
def mock_response():
    """Mock aiohttp response"""
    response = MagicMock()
    response.status = 200
    response.headers = {'content-type': 'text/html'}
    response.text = MagicMock()
    response.text.return_value = "test content"
    return response

@pytest.mark.asyncio
async def test_secure_session_creation():
    """Test creating a secure session with custom config"""
    config = SessionConfig(
        proxy=None,
        user_agent_pool=["Test Agent"],
        timeout=5.0,
        verify_ssl=False,
        max_redirects=3,
        rate_limit=1.0
    )
    
    session = await SessionManager.create_secure_session(config)
    assert isinstance(session, aiohttp.ClientSession)
    # Verify timeout setting
    assert session._timeout.total == 5.0
    # Verify headers
    headers = session._default_headers
    assert 'Test Agent' in headers.get('User-Agent', '')
    assert 'close' in headers.get('Connection', '')
    await session.close()

@pytest.mark.asyncio
async def test_default_session_creation():
    """Test creating a session with default config"""
    session = await SessionManager.create_secure_session()
    assert isinstance(session, aiohttp.ClientSession)
    assert session._timeout.total == 30.0
    headers = session._default_headers
    assert any(ua in headers.get('User-Agent', '') for ua in SessionManager.DEFAULT_USER_AGENTS)
    await session.close()

@patch('aiohttp.ClientSession', autospec=True)
def test_load_config_from_file(mock_session_class, mock_response):
    """Test loading configuration from YAML file"""
    mock_session = mock_session_class.return_value
    mock_session.get.return_value.__aenter__.return_value = mock_response
    
    config = SessionManager.load_config()
    assert config.timeout == 30.0
    assert config.verify_ssl is False
    assert config.max_redirects == 3
    assert config.proxy is None
    assert config.user_agent_pool == SessionManager.DEFAULT_USER_AGENTS

def test_load_config_defaults():
    """Test loading default configuration when file not found"""
    config = SessionConfig()
    assert config.timeout == 30.0
    assert config.verify_ssl is False
    assert config.max_redirects == 3
    assert config.proxy is None
    assert isinstance(config.user_agent_pool, list)

def test_secure_headers_generation():
    """Test generating secure request headers"""
    config = SessionConfig(user_agent_pool=["Test Agent"])
    headers = SessionManager._get_secure_headers(config)
    assert 'User-Agent' in headers
    assert headers['User-Agent'] == 'Test Agent'
    assert 'Accept' in headers
    assert 'Accept-Language' in headers
    assert 'Accept-Encoding' in headers
    assert headers['Connection'] == 'close'

@pytest.mark.asyncio
async def test_secure_request_success(mock_session, mock_response):
    """Test successful secure HTTP request"""
    with patch('aiohttp.ClientSession', return_value=mock_session):
        response = await SessionManager.secure_request('http://test.local')
        assert response.status == 200

@pytest.mark.asyncio
async def test_secure_request_with_proxy(mock_session, mock_response):
    """Test request with proxy configuration"""
    config = SessionConfig(
        proxy='test-proxy:8080',
        user_agent_pool=['Test Agent']
    )
    
    with patch('aiohttp.ClientSession', return_value=mock_session):
        response = await SessionManager.secure_request('http://test.local', config=config)
        assert response.status == 200
        assert mock_session._proxy == 'http://test-proxy:8080'

@pytest.mark.asyncio
async def test_invalid_url(mock_session):
    """Test request with invalid URL"""
    url = 'not-a-url'
    with pytest.raises(ValidationError, match=f"Invalid URL: {url}"):
        await SessionManager.secure_request(url)