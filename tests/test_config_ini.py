import json

from mpush_analyzer.config_ini import parse_agent_ini

SYNTHETIC_INI = """[AGENT]
id=A1
type=real
[ENCRYPT_ITEM]
clientPlainKey=SYNTHETIC_PLAINKEY_DO_NOT_COPY
[SERVICE]
service=9876543210
[DBMS]
type=mysql
url=jdbc:mysql://192.0.2.42:3306/DEMO
username=synthetic_user
password=SYNTHETIC_PASSWORD_DO_NOT_COPY
connectiontimeout=2500
maxlifetime=45000
idletimeout=1200
[HA]
timeout_sec=15
use=yes
[JOB_SELECT]
send_real_file_image=Y
ha_receive_result=Y
[TEST]
tcp_server=198.51.100.10
tcp_port=13456
[REAL]
tcp_server=203.0.113.4
tcp_port=13457
"""


def test_ini_allowlist_and_no_values_in_summary():
    s = parse_agent_ini(SYNTHETIC_INI)
    assert s["agent"]["id_present"] is True
    assert s["agent"]["run_type"] == "real"
    assert s["service"]["service_present"] is True
    assert s["dbms"]["type"] == "mysql"
    assert s["dbms"]["connectiontimeout"] == 2500
    assert s["ha"]["timeout_sec"] == 15
    assert s["ha"]["enabled"] is True
    assert s["target_endpoints"]["real"]["tcp_host_configured"]
    assert "SEND_REAL_FILE_IMAGE" in s["job_select"]["keys_present"]
    rendered = json.dumps(s)
    for secret in ("SYNTHETIC_PASSWORD", "SYNTHETIC_PLAINKEY", "9876543210", "192.0.2.42", "203.0.113.4", "jdbc:mysql", "synthetic_user"):
        assert secret not in rendered


def test_ini_tolerates_bad_lines_and_duplicate_keys():
    s = parse_agent_ini(
        "[AGENT]\nid=A1\nid=A2\nBAD_LINE\n[DBMS]\ntype=oracle\n"
    )
    assert s["agent"]["id_present"]
    assert len(s["warnings"]) == 2
    assert s["dbms"]["type"] == "oracle"


def test_unknown_values_not_leaked():
    s = parse_agent_ini("[AGENT]\nid=sensitive\ntype=STRANGE_HIDDEN\n[DBMS]\ntype=SUPERSECRETDB\n")
    result = json.dumps(s)
    assert "STRANGE_HIDDEN" not in result
    assert "SUPERSECRETDB" not in result
    assert s["dbms"]["type"] == "unknown"
