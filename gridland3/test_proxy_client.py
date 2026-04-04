import os
from plugins.vulnerability_scanner import VulnerabilityScannerPlugin
from lib.core import ScanTarget, PortResult

def run_test():
    """
    Calls the vulnerability scanner to test proxy integration.
    """
    # Set the proxy environment variable
    os.environ['PROXY_URL'] = 'http://127.0.0.1:8888'

    target = ScanTarget(
        ip='192.168.1.1', # This IP doesn't matter as it will be proxied
        open_ports=[PortResult(port=80, is_open=True)]
    )
    plugin = VulnerabilityScannerPlugin()

    print("--- Testing Proxy Integration ---")
    plugin.scan(target)
    print("--- Test Complete ---")

    # Unset the proxy variable
    del os.environ['PROXY_URL']


if __name__ == '__main__':
    run_test()
