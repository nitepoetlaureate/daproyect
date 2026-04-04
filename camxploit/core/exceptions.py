"""
Exception hierarchy for CamXploit
Provides clean exception handling for operational clarity
"""

class CamXploitError(Exception):
    """Base exception for all CamXploit errors"""
    pass


class ValidationError(CamXploitError):
    """Raised when input validation fails"""
    
    def __init__(self, message: str):
        super().__init__(message)


class ScanError(CamXploitError):
    """Raised when scanning operations fail"""
    
    def __init__(self, message: str):
        super().__init__(message)


class AuthenticationError(CamXploitError):
    """Raised when authentication fails"""
    
    def __init__(self, message: str):
        super().__init__(message)


class NetworkError(CamXploitError):
    """Raised for network-related errors"""
    
    def __init__(self, message: str):
        super().__init__(message)


class ConfigurationError(CamXploitError):
    """Raised for configuration issues"""
    pass


class ResourceExhaustedError(CamXploitError):
    """Raised when system resources are exhausted"""
    
    def __init__(self, message: str):
        super().__init__(message)
