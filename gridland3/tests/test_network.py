import pytest
from unittest.mock import patch, MagicMock
from lib.core import PortResult
from lib.network import check_port, scan_ports

@patch('socket.socket')
def test_check_port_open(mock_socket):
    """
    Tests that check_port correctly identifies an open port and grabs a banner.
    """
    # Arrange
    mock_sock_instance = MagicMock()
    mock_sock_instance.connect_ex.return_value = 0  # 0 means the port is open
    mock_sock_instance.recv.return_value = b'SSH-2.0-OpenSSH_7.4\r\n'
    mock_socket.return_value.__enter__.return_value = mock_sock_instance

    # Act
    result = check_port('127.0.0.1', 22)

    # Assert
    assert isinstance(result, PortResult)
    assert result.is_open is True
    assert result.port == 22
    assert result.banner == 'SSH-2.0-OpenSSH_7.4'
    mock_sock_instance.connect_ex.assert_called_once_with(('127.0.0.1', 22))
    mock_sock_instance.recv.assert_called_once_with(1024)

@patch('socket.socket')
def test_check_port_closed(mock_socket):
    """
    Tests that check_port correctly identifies a closed port.
    """
    # Arrange
    mock_sock_instance = MagicMock()
    mock_sock_instance.connect_ex.return_value = 1  # Non-zero means closed/filtered
    mock_socket.return_value.__enter__.return_value = mock_sock_instance

    # Act
    result = check_port('127.0.0.1', 80)

    # Assert
    assert isinstance(result, PortResult)
    assert result.is_open is False
    assert result.port == 80
    assert result.banner is None
    mock_sock_instance.connect_ex.assert_called_once_with(('127.0.0.1', 80))
    mock_sock_instance.recv.assert_not_called()

@patch('lib.network.check_port')
def test_scan_ports(mock_check_port):
    """
    Tests that scan_ports correctly uses a thread pool to scan multiple ports
    and returns only the open ones.
    """
    # Arrange
    ports_to_scan = [22, 80, 443, 8080]
    mock_results = [
        PortResult(port=22, is_open=True, banner='SSH'),
        PortResult(port=80, is_open=False),
        PortResult(port=443, is_open=True, banner='HTTPS'),
        PortResult(port=8080, is_open=False),
    ]
    # The side_effect of a mock can be an iterable. Each time the mock is called,
    # it returns the next item from the iterable.
    mock_check_port.side_effect = mock_results

    # Act
    results = scan_ports('127.0.0.1', ports_to_scan, max_threads=4)

    # Assert
    assert len(results) == 2
    assert results[0].port == 22
    assert results[1].port == 443
    assert results[0].banner == 'SSH'
    assert mock_check_port.call_count == 4
