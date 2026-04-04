from plugins.stream_scanner import StreamScannerPlugin
from lib.core import ScanTarget, PortResult

def run_test():
    """
    Tests that the stream scanner correctly verifies streams and only
    reports valid ones.
    """
    # We need to override the default HTTP_PATHS to point to our test server
    StreamScannerPlugin.HTTP_PATHS = ['/good_stream', '/bad_stream']

    target = ScanTarget(
        ip='127.0.0.1',
        open_ports=[PortResult(port=8888, is_open=True)]
    )
    plugin = StreamScannerPlugin()

    print("--- Testing Stream Verification ---")
    findings = plugin.scan(target)

    print(f"Found {len(findings)} findings.")
    for finding in findings:
        print(f"  - {finding.description}")
        assert "good_stream" in finding.url

    assert len(findings) == 1
    print("--- Test Complete ---")

if __name__ == '__main__':
    run_test()
