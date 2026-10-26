from pathlib import Path


def test_streamlit_app_boots_without_uploaded_data():
    from streamlit.testing.v1 import AppTest

    path = Path(__file__).resolve().parents[1] / "app.py"
    test_app = AppTest.from_file(str(path), default_timeout=15).run()
    assert len(test_app.exception) == 0, [str(x.message) for x in test_app.exception]
    assert any("MPushAgent Log Analyzer" in x.value for x in test_app.title)
    assert len(test_app.get("file_uploader")) >= 2
    assert [tab.label for tab in test_app.tabs] == [
        "분석 대시보드", "로그 업로드", "해결 사례", "보고서·관리"
    ]
