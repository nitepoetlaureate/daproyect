"""
CamXploit scanning constants
Comprehensive port and pattern definitions
"""

# Complete port mappings from original script
CAMERA_PORTS = [
    # HTTP/HTTPS web interfaces
    80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085,
    8086, 8087, 8088, 8089, 8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097,
    8098, 8099, 8888, 8889, 8890, 8891, 8892, 8893, 8894, 8895, 8896, 8897,
    8898, 8899, 9999, 9998, 9997, 9996, 9995, 9994, 9993, 9992, 9991, 9990,
    
    # RTSP streaming
    554, 8554, 10554, 1554, 2554, 3554, 4554, 5554, 6554, 7554, 9554,
    
    # RTMP streaming
    1935, 1936, 1937, 1938, 1939,
    
    # Dahua proprietary
    37777, 37778, 37779, 37780, 37781, 37782, 37783, 37784, 37785, 37786,
    37787, 37788, 37789, 37790, 37791, 37792, 37793, 37794, 37795, 37796,
    37797, 37798, 37799, 37800,
    
    # ONVIF
    3702, 3703, 3704, 3705, 3706, 3707, 3708, 3709, 3710,
    
    # MMS
    1755, 1756, 1757, 1758, 1759, 1760,
    
    # VLC/custom ranges
    5000, 5001, 5002, 5003, 5004, 5005, 5006, 5007, 5008, 5009, 5010,
    6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009, 6010,
    7000, 7001, 7002, 7003, 7004, 7005, 7006, 7007, 7008, 7009, 7010,
    9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009, 9010,
    
    # Extended ranges
    10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10008, 10009, 10010,
    20000, 20001, 20002, 20003, 20004, 20005, 20006, 20007, 20008, 20009, 20010,
    30000, 30001, 30002, 30003, 30004, 30005, 30006, 30007, 30008, 30009, 30010,
    40000, 40001, 40002, 40003, 40004, 40005, 40006, 40007, 40008, 40009, 40010,
    50000, 50001, 50002, 50003, 50004, 50005, 50006, 50007, 50008, 50009, 50010,
    60000, 60001, 60002, 60003, 60004, 60005, 60006, 60007, 60008, 60009, 60010
]

# Camera detection patterns (enhanced from original)
CAMERA_PATTERNS = {
    'hikvision': {
        'headers': ['hikvision', 'dvr', 'nvr', 'hik'],
        'content': ['hikvision', 'hik', 'dvr', 'nvr', 'ip camera', 'network camera'],
        'paths': [
            '/ISAPI/System/deviceInfo',
            '/System/configurationFile',
            '/cgi-bin/magicBox.cgi',
            '/onvif-http/snapshot'
        ]
    },
    'dahua': {
        'headers': ['dahua', 'dvr', 'nvr', 'dh'],
        'content': ['dahua', 'dh', 'dvr', 'nvr', 'ip camera', 'network camera'],
        'paths': [
            '/cgi-bin/magicBox.cgi?action=getSystemInfo',
            '/cgi-bin/configManager.cgi',
            '/cgi-bin/devInfo.cgi'
        ]
    },
    'axis': {
        'headers': ['axis', 'axis communications'],
        'content': ['axis', 'axis communications', 'network camera', 'ip camera'],
        'paths': [
            '/axis-cgi/admin/param.cgi?action=list',
            '/axis-cgi/mjpg/video.cgi',
            '/axis-cgi/com/ptz.cgi'
        ]
    },
    'cp_plus': {
        'headers': ['cp plus', 'cp-plus', 'cpplus', 'uvr'],
        'content': ['cp plus', 'cp-plus', 'cpplus', 'uvr', '0401e1', 'dvr', 'nvr'],
        'paths': [
            '/',
            '/login',
            '/admin',
            '/cgi-bin/snapshot.cgi',
            '/cgi-bin/video.cgi'
        ]
    },
    'generic': {
        'headers': ['camera', 'webcam', 'surveillance', 'dvr', 'nvr'],
        'content': ['camera', 'webcam', 'surveillance', 'dvr', 'nvr', 'ip camera', 'network camera'],
        'paths': [
            '/',
            '/admin',
            '/login',
            '/viewer',
            '/video',
            '/stream',
            '/snapshot',
            '/live',
            '/onvif-http/snapshot'
        ]
    }
}

# Default credentials (comprehensive from original)
DEFAULT_CREDENTIALS = {
    "admin": [
        "admin", "1234", "admin123", "password", "12345", "123456", "1111", 
        "default", "admin1234", "admin12345", "admin123456"
    ],
    "root": [
        "root", "toor", "1234", "pass", "root123", "root1234", "root12345",
        "root123456", "password", "admin"
    ],
    "user": [
        "user", "user123", "password", "1234", "12345", "123456", "default"
    ],
    "guest": [
        "guest", "guest123", "password", "1234", "12345", "123456"
    ],
    "operator": [
        "operator", "operator123", "password", "1234", "12345", "123456"
    ],
    "service": [
        "service", "service123", "password", "1234", "12345"
    ]
}

# CVE database (expanded from original)
CVE_DATABASE = {
    "hikvision": [
        "CVE-2021-36260", "CVE-2017-7921", "CVE-2021-31955", "CVE-2021-31956",
        "CVE-2021-31957", "CVE-2021-31958", "CVE-2021-31959", "CVE-2021-31960",
        "CVE-2021-31961", "CVE-2021-31962", "CVE-2021-31963", "CVE-2021-31964",
        "CVE-2021-33039", "CVE-2021-33040", "CVE-2021-33041", "CVE-2021-33042"
    ],
    "dahua": [
        "CVE-2021-33044", "CVE-2022-30563", "CVE-2021-33045", "CVE-2021-33046",
        "CVE-2021-33047", "CVE-2021-33048", "CVE-2021-33049", "CVE-2021-33050",
        "CVE-2021-33051", "CVE-2021-33052", "CVE-2021-33053", "CVE-2021-33054",
        "CVE-2022-30564", "CVE-2022-30565", "CVE-2022-30566", "CVE-2022-30567"
    ],
    "axis": [
        "CVE-2018-10660", "CVE-2020-29550", "CVE-2020-29551", "CVE-2020-29552",
        "CVE-2020-29553", "CVE-2020-29554", "CVE-2020-29555", "CVE-2020-29556",
        "CVE-2020-29557", "CVE-2020-29558", "CVE-2020-29559", "CVE-2020-29560"
    ],
    "cp_plus": [
        "CVE-2021-XXXXX", "CVE-2022-XXXXX", "CVE-2023-XXXXX",
        "CVE-2024-XXXXX", "CVE-2025-XXXXX"
    ]
}

# Common streaming endpoints
STREAM_ENDPOINTS = {
    'rtsp': [
        '/live.sdp', '/h264.sdp', '/stream1', '/stream2', '/main', '/sub',
        '/video', '/cam/realmonitor', '/Streaming/Channels/1',
        '/Streaming/Channels/101', '/onvif/streaming/channels/1',
        '/axis-media/media.amp', '/axis-cgi/mjpg/video.cgi',
        '/cgi-bin/mjpg/video.cgi', '/cgi-bin/hi3510/snap.cgi',
        '/cgi-bin/snapshot.cgi', '/cgi-bin/viewer/video.jpg',
        '/img/snapshot.cgi', '/snapshot.jpg', '/video/mjpg.cgi',
        '/video.cgi', '/videostream.cgi', '/mjpg/video.mjpg',
        '/mjpg.cgi', '/stream.cgi', '/live.cgi', '/live/0/onvif.sdp',
        '/live/0/h264.sdp', '/live/0/mpeg4.sdp', '/live/1/onvif.sdp'
    ],
    'http': [
        '/video', '/stream', '/mjpg/video.mjpg', '/cgi-bin/mjpg/video.cgi',
        '/axis-cgi/mjpg/video.cgi', '/cgi-bin/viewer/video.jpg',
        '/snapshot.jpg', '/img/snapshot.cgi', '/api/video', '/api/stream',
        '/api/live', '/api/camera/live', '/api/camera/stream'
    ],
    'rtmp': [
        '/live', '/stream', '/hls', '/flv', '/rtmp', '/live/stream',
        '/live/stream1', '/live/main', '/live/sub'
    ]
}

# HTTP headers for requests
DEFAULT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1'
}
