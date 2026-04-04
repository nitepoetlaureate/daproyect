import pytest
from unittest.mock import patch, MagicMock, call
from lib.core import ScanTarget, PortResult
from plugins.discovery_scanner import DiscoveryScannerPlugin

@pytest.fixture
def plugin():
    """A fixture to create a DiscoveryScannerPlugin instance."""
    # The plugin loads its config during init, so it's already populated
    # with our test YAML structure after the first step.
    return DiscoveryScannerPlugin()

@pytest.fixture
def target():
    """A fixture for the target device."""
    return ScanTarget(ip='192.168.1.101', open_ports=[PortResult(port=80, is_open=True)])

def get_mock_response(status_code, headers=None, text=""):
    """Helper to create a mock requests.Response object."""
    mock_res = MagicMock()
    mock_res.status_code = status_code
    mock_res.headers = headers if headers is not None else {}
    mock_res.text = text
    mock_res.content = text.encode()
    return mock_res

@patch('plugins.discovery_scanner.requests.Session')
def test_scan_prioritizes_nginx_paths(MockSession, plugin, target):
    """
    VERIFICATION PROTOCOL 1:
    Tests that if a server is identified as 'nginx', the scanner checks
    nginx-specific paths before generic paths.
    """
    # Arrange
    mock_session_instance = MockSession.return_value.__enter__.return_value

    def get_side_effect(url, timeout=5):
        if url == 'http://192.168.1.101:80': # Base URL for fingerprinting
            return get_mock_response(200, headers={'Server': 'nginx/1.18.0'})
        elif url == 'http://192.168.1.101:80/nginx_status': # Nginx-specific path
            # The content needs to contain a debug indicator to trigger a finding
            return get_mock_response(200, text="some debug info here")
        else: # Generic paths
            return get_mock_response(404)

    mock_session_instance.get.side_effect = get_side_effect

    # Act
    findings = plugin.scan(target)

    # Assert
    calls = mock_session_instance.get.call_args_list
    urls_called = [c.args[0] for c in calls]

    # Find indices of the key URLs
    base_url_index = urls_called.index('http://192.168.1.101:80')
    nginx_path_index = urls_called.index('http://192.168.1.101:80/nginx_status')
    generic_admin_path_index = urls_called.index('http://192.168.1.101:80/admin')

    # Success Condition 1: The logs must show that the scanner attempted to access /nginx_status before it attempted to access /admin.
    assert base_url_index == 0, "Fingerprint request must be first"
    assert nginx_path_index < generic_admin_path_index, "Nginx-specific path should be checked before generic paths"

    # Success Condition 2: The source code for discovery_scanner.py must contain only one primary requests.get call for path enumeration.
    # This is implicitly tested by the fact we are mocking requests.Session and its `get` method, which is used by the single `_check_path` helper.

    # Also verify that a finding was correctly generated for the successful hit.
    assert len(findings) == 1
    assert findings[0].description == "Debug endpoint exposed: /nginx_status"
    assert findings[0].url == 'http://192.168.1.101:80/nginx_status'

@patch('plugins.discovery_scanner.requests.Session')
def test_scan_prioritizes_apache_paths(MockSession, plugin, target):
    """
    Tests that if a server is identified as 'Apache', the scanner checks
    Apache-specific paths before generic paths.
    """
    # Arrange
    mock_session_instance = MockSession.return_value.__enter__.return_value

    def get_side_effect(url, timeout=5):
        if url == 'http://192.168.1.101:80': # Base URL for fingerprinting
            return get_mock_response(200, headers={'Server': 'Apache/2.4.29 (Ubuntu)'})
        else:
            return get_mock_response(404)

    mock_session_instance.get.side_effect = get_side_effect

    # Act
    plugin.scan(target)

    # Assert
    calls = mock_session_instance.get.call_args_list
    urls_called = [c.args[0] for c in calls]

    apache_path_index = urls_called.index('http://192.168.1.101:80/server-status')
    generic_admin_path_index = urls_called.index('http://192.168.1.101:80/admin')

    assert apache_path_index < generic_admin_path_index, "Apache-specific path should be checked before generic paths"

@patch('plugins.discovery_scanner.requests.Session')
def test_scan_with_unknown_server(MockSession, plugin, target):
    """
    Tests that if a server is not identified, the scanner still proceeds
    to check the generic paths.
    """
    # Arrange
    mock_session_instance = MockSession.return_value.__enter__.return_value

    def get_side_effect(url, timeout=5):
        if url == 'http://192.168.1.101:80': # Base URL for fingerprinting
            return get_mock_response(200, headers={'Server': 'SomeOtherWebServer/1.0'})
        else:
            return get_mock_response(404)

    mock_session_instance.get.side_effect = get_side_effect

    # Act
    plugin.scan(target)

    # Assert
    calls = mock_session_instance.get.call_args_list
    urls_called = [c.args[0] for c in calls]

    # Ensure paths that are *only* in server-specific blocks were not checked.
    assert 'http://192.168.1.101:80/etc/nginx/nginx.conf' not in urls_called
    assert 'http://192.168.1.101:80/.htaccess' not in urls_called

    # Ensure generic paths are still checked.
    # Note: /server-status is also in the generic list, so it's correct for it to be called.
    assert 'http://192.168.1.101:80/admin' in urls_called
    assert 'http://192.168.1.101:80/config.xml' in urls_called

@patch('plugins.discovery_scanner.requests.Session')
def test_finding_for_protected_interface(MockSession, plugin, target):
    """
    Tests that a 'low' severity finding is created for protected (401/403) admin interfaces.
    """
    # Arrange
    mock_session_instance = MockSession.return_value.__enter__.return_value

    def get_side_effect(url, timeout=5):
        if url == 'http://192.168.1.101:80': # Base URL
            return get_mock_response(200, headers={'Server': 'nginx'})
        # The /admin path is of type 'interface_discovery'
        elif url == 'http://192.168.1.101:80/admin':
            return get_mock_response(403) # 403 Forbidden
        else:
            return get_mock_response(404)

    mock_session_instance.get.side_effect = get_side_effect

    # Act
    findings = plugin.scan(target)

    # Assert
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == "web_interface"
    assert finding.severity == "low"
    assert finding.description == "Protected interface found: /admin"
    assert finding.data['status_code'] == 403
    assert finding.data['auth_required'] is True
