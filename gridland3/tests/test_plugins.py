import pytest
from unittest.mock import patch, MagicMock
from lib.core import ScanTarget, PortResult
from plugins.credential_scanner import CredentialScannerPlugin
from lib.evasion import get_request_headers

@patch('requests.get')
def test_credential_scanner_plugin_success(mock_get):
    """
    Tests that the CredentialScannerPlugin correctly identifies credentials
    when a valid login is found.
    """
    # Arrange
    # This response should not trigger the "failed login" indicators
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "Welcome to the dashboard."
    mock_get.return_value = mock_response

    target = ScanTarget(
        ip='192.168.1.100',
        open_ports=[PortResult(port=80, is_open=True)]
    )

    plugin = CredentialScannerPlugin()

    # Act
    findings = plugin.scan(target)

    # Assert
    # The plugin should find the first credential in its list and then stop.
    # The first credential for 'admin' is an empty password.
    assert len(findings) == 1

    finding = findings[0]
    assert finding.category == "credential"

    # The first endpoint checked is the base URL
    expected_endpoint = 'http://192.168.1.100:80/'
    expected_description = f"Found default credentials admin: on {expected_endpoint}"
    assert finding.description == expected_description

    assert finding.data['username'] == 'admin'
    assert finding.data['password'] == ''

    # Verify that the request was made with the correct parameters
    call_kwargs = mock_get.call_args.kwargs
    assert call_kwargs['auth'] == ('admin', '')
    assert call_kwargs['proxies'] is None
    assert call_kwargs['timeout'] == 3
    assert call_kwargs['verify'] is False
    assert mock_get.call_args.args[0] == expected_endpoint
