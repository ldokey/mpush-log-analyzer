"""Windows launch contract tests runnable on Mac/Linux without CMD.

These checks are not proof of native Windows runtime behavior.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_windows_root_launcher_exists_and_delegates():
    launcher = (ROOT / "START_WINDOWS.bat").read_bytes()
    assert b"\r\n" in launcher
    assert rb'call "%~dp0scripts\run_windows.bat"' in launcher
    assert b"exit /b %errorlevel%" in launcher


def test_windows_runner_local_and_environment_checks():
    runner = (ROOT / "scripts/run_windows.bat").read_text(encoding="ascii")
    assert r'cd /d "%~dp0\.."' in runner
    assert 'if not exist "app.py"' in runner
    assert 'if not exist "requirements.txt"' in runner
    assert 'py -3.13 -m venv ".venv"' in runner
    assert 'python -m venv ".venv"' in runner
    assert "sys.version_info[:2] == (3,13)" in runner
    assert "struct.calcsize('P') == 8" in runner
    assert r'if exist ".venv\bin\python" goto FOREIGN_VENV' in runner
    assert '-m pip install --disable-pip-version-check -r requirements.txt' in runner
    assert 'streamlit run app.py --server.address 127.0.0.1 --server.port 8501' in runner
    assert '--browser.gatherUsageStats false' in runner
    assert "0.0.0.0" not in runner


def test_windows_docs_are_linked():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    guide = (ROOT / "docs/WINDOWS_QUICK_START.md").read_text(encoding="utf-8")
    assert "START_WINDOWS.bat" in readme
    assert "docs/WINDOWS_QUICK_START.md" in readme
    for needed in ("START_WINDOWS.bat", "Python 3.13", "127.0.0.1:8501",
                   "NTFS ACL", "Ctrl+C", "실제 Windows"):
        assert needed in guide
