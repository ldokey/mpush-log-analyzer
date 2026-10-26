"""Cross-platform mode wrapper does not raise on Windows-style filesystem APIs."""
from __future__ import annotations
from unittest.mock import Mock, patch
from mpush_analyzer.fs_compat import private_file_mode


def test_posix_private_permissions():
    with patch("mpush_analyzer.fs_compat.os") as os_mock:
        os_mock.name = "posix"
        private_file_mode(8, 0o600)
        os_mock.fchmod.assert_called_once_with(8, 0o600)


def test_windows_permission_wrapper_does_not_call_fchmod():
    with patch("mpush_analyzer.fs_compat.os") as os_mock:
        os_mock.name = "nt"
        os_mock.fchmod = Mock(side_effect=AttributeError("not available"))
        private_file_mode(8, 0o600)
        os_mock.fchmod.assert_not_called()
