"""
core/errors.py — Custom exception hierarchy for Corvida.

Using typed exceptions means callers can selectively catch exactly what
they care about without inspecting message strings.
"""


class CorvidaError(Exception):
    """Base class for all Corvida errors."""


class UnsupportedFormatError(CorvidaError):
    """Raised when no loader can handle the given file."""


class LoaderError(CorvidaError):
    """Raised when a loader fails to parse the file."""


class BackendUnavailableError(CorvidaError):
    """
    Raised when a required backend (rizin, pwntools, …) is not installed.

    The message should include installation instructions.
    """


class BackendError(CorvidaError):
    """Raised when a backend call returns an unexpected result."""


class AnalyzerError(CorvidaError):
    """Raised when an analyzer encounters an unrecoverable error."""


class RuleError(CorvidaError):
    """Raised when a rules YAML file is malformed or missing."""
