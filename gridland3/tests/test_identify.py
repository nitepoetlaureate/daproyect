import pytest
from unittest.mock import patch, MagicMock
from lib.core import PortResult
from lib.identify import identify_device

@patch('requests.get')
def test_identify_hikvision_camera(mock_get):
    """
    Tests that the identify_device function can identify a Hikvision camera
    from the content of its web page.
    """
    # Arrange
    ip = '192.168.1.100'
    open_ports = [PortResult(port=80, is_open=True, banner='')]

    # Mock the response from requests.get
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = '<html><title>HIKVISION</title></html>'
    mock_response.headers = {'Server': 'nginx'}
    mock_get.return_value = mock_response

    # Act
    device_type, brand = identify_device(ip, open_ports)

    # Assert
    assert device_type == 'IP Camera'
    assert brand == 'hikvision'
    mock_get.assert_called_once_with(
        'http://192.168.1.100:80',
        headers={'User-Agent': 'Mozilla/5.0 Security Scanner'},
        timeout=5,
        verify=False
    )
