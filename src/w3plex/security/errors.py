"""Safe error codes. Never include dependency exceptions or private values."""


class SecurityError(Exception):
    code = "security_error"

    def __init__(self):
        super().__init__(self.code)


class InteractionRequired(SecurityError):
    code = "interaction_required"


class AuthenticationFailed(SecurityError):
    code = "authentication_failed"


class InvalidStore(SecurityError):
    code = "invalid_store"


class UnsupportedProtection(SecurityError):
    code = "protection_unavailable"


class PermissionDenied(SecurityError):
    code = "permission_denied"


class ActivationConflict(SecurityError):
    code = "encrypted_io_conflict"
