from __future__ import annotations

from mpush_analyzer.parsers import parse_by_kind
from mpush_analyzer.parsers.common import ClockResolver


def parsed(kind: str, text: str):
    return list(parse_by_kind(kind, enumerate(text.splitlines(), start=1)))


def test_job_complete_two_types_and_incomplete():
    log = """04:30:02[092] Starting....
04:30:02[728] Started
08:37:11[248]

##  SEND_REAL_FILE_IMAGE 작업
08:37:11[248] ##  작업대상건수  : 2
08:37:11[248] ##  시작시간 : 8시 37분 11.0초
08:37:11[248] ##  종료시간 : 8시 37분 11.248초
08:37:11[248] ##  SELECT 시간(초.0f) : 0.006초
08:37:11[248] ##  FILE 시간(초.0f) : 0.142초
08:37:11[248] ##  SOCKET 시간(초.0f) : 0.1초
08:37:11[248] ##  소요시간(초.0f) : 0.248초
08:37:11[248] ##  초당 작업 건수  : 4.032258건
08:37:20[244]

##  HA_RECEIVE_RESULT 작업
08:37:20[244] ##  작업대상건수  : 1
08:37:20[244] ##  시작시간 : 8시 37분 20.1초
08:37:20[244] ##  종료시간 : 8시 37분 20.243초
08:37:20[244] ##  HTTP IN 시간(초.0f) : 0.202초
08:37:20[244] ##  DB 시간(초.0f) : 0.006초
08:37:20[244] ##  HTTP OUT 시간(초.0f) : 0.034초
08:37:20[244] ##  소요시간(초.0f) : 0.242초
08:37:20[244] Done
08:37:30[080]

##  SEND_REAL_FILE_IMAGE 작업
08:37:30[080] ##  작업대상건수  : 3
"""
    items = parsed("job", log)
    assert [e.kind for e in items] == [
        "agent_starting", "agent_started", "job_run", "job_run", "job_run"
    ]
    first, second, third = items[2:]
    assert first.data["job_name"] == "SEND_REAL_FILE_IMAGE"
    assert first.data["target_count"] == 2
    assert first.data["duration_seconds"] == 0.248
    assert first.data["reported_tps"] == 4.032258
    assert first.data["steps_seconds"] == {"select": 0.006, "file": 0.142, "socket": 0.1}
    assert first.status == "complete"
    assert second.data["steps_seconds"]["http_out"] == 0.034
    assert second.status == "complete"
    assert third.status == "incomplete"
    assert first.start_line == 5
    assert second.clock == "08:37:20.243"


def test_dbwrap_eq_eu_eb_and_no_query_text():
    log = """10:10:08[003]
NO_ID_-124=PSTMT.EQ Laptime : 7
NO_ID_-124=        SELECT MESSAGE_ID
NO_ID_-124=        FROM secret_schema.message_table
NO_ID_-124=        WHERE CLIENT_PLAIN_KEY='SECRET_TEST_VALUE'
NO_ID_-124=Result : select completed.
10:10:09[002]
NO_ID_456=PSTMT.EU Laptime : 1800
NO_ID_456=UPDATE secret_schema.message_table SET SENSITIVE_VALUE='SECRET_TEST_VALUE'
NO_ID_456=Result : 0 row(s) updated.
10:10:12[006]
NO_ID_-9=PSTMT.EB Laptime : 117 Result : batch job success.
"""
    items = parsed("dbwrap", log)
    assert len(items) == 3
    assert [x.data["statement_kind"] for x in items] == ["EQ", "EU", "EB"]
    assert [x.data["sql_operation"] for x in items] == ["SELECT", "UPDATE", "UNKNOWN"]
    assert [x.data["outcome"] for x in items] == ["select_completed", "rows_affected", "batch_success"]
    assert items[1].data["affected_rows"] == 0
    assert items[1].data["laptime_ms"] == 1800.0
    assert items[0].start_line == 1 and items[0].end_line == 6
    assert all("SECRET" not in str(e) for e in items)
    assert all(e.status == "complete" for e in items)


def test_debug_response_is_acceptance_not_delivery():
    log = """10:11:40[001] 헬스 체크 서비스 번호 : 999888777
10:11:40[181] httpClientToTSMSHealthCheck resulStr ==>> {"TARGET":"Nothing"}
10:11:40[181] 헬스 체크 결과 : {"TARGET":"Nothing"}
10:11:45[101] ***************** 서버에서 받은 문자열 [{"RESPONSE_CODE":"S"}]
10:11:45[104] 소켓 전송 성공 resultMessage : RESPONSE_CODE value : S
10:11:50[001] -- Can't execute task in RUNNING state :: SEND_REAL_FILE_IMAGE --
10:11:51[001] ***************** 서버에서 받은 문자열 [{"RESPONSE_CODE":"E"}]
10:11:52[001] myToken=SECRET_1234
"""
    items = parsed("debug", log)
    assert [e.kind for e in items] == [
        "healthcheck_request", "healthcheck_result", "cns_response", "job_running_skip", "cns_response"
    ]
    assert items[1].data == {"target_action": "no_action"}
    assert items[2].data == {
        "response_code": "S",
        "interpretation": "request_accepted",
        "final_delivery_confirmed": False,
    }
    assert items[3].data["job_name"] == "SEND_REAL_FILE_IMAGE"
    assert all("SECRET" not in str(x) for x in items)


def test_info_and_err_multiline_exception():
    info = """04:30:02[663] *HA_RECEIVE_RESULT 은 */10 * * * * ? 으로 예약 되었습니다.
04:30:02[664] [HttpClientTemplate] Connection pool initialized.
08:37:11[207] 클라이언트 소켓 연결 되었습니다.
08:37:11[211] 서버로의 파일전송이 완료 되었습니다.
"""
    i = parsed("info", info)
    assert i[0].kind == "scheduler_registration"
    assert i[0].data["job_name"] == "HA_RECEIVE_RESULT"
    assert i[1].data == {"state": "socket_connected"}
    assert i[2].data == {"state": "file_transfer_completed"}
    err = """10:11:55[007] java.net.SocketTimeoutException: SECRET_TOKEN_99999999
  at com.synthetic.Network.call(Network.java:25)
Caused by: java.io.IOException: secret.example.org
  at com.synthetic.A.run(A.java:4)
10:12:00[002] java.lang.RuntimeException: secret
  at com.synthetic.B.run(B.java:7)
"""
    e = parsed("err", err)
    assert len(e) == 2
    assert e[0].data["exception_class"] == "SocketTimeoutException"
    assert e[0].start_line == 1 and e[0].end_line == 4
    assert e[0].data["stack_frame_count"] >= 2
    assert "secret" not in str(e).lower()


def test_clock_midnight_and_nonmonotonic():
    c = ClockResolver(__import__("datetime").date(2026, 10, 15))
    got = [c.normalize(x)[0] for x in (
        "23:59:59.950", "00:00:00.001", "00:00:10.000", "00:00:09.800"
    )]
    assert got[0].startswith("2026-10-15T")
    assert got[1].startswith("2026-10-16T")
    assert c.rollovers == 1 and c.out_of_order == 1
    no_date = ClockResolver(None)
    assert no_date.normalize("12:00:00.000") == (None, "clock_only")
