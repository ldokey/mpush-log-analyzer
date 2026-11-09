from pathlib import Path


def test_streamlit_app_boots_without_uploaded_data():
    from streamlit.testing.v1 import AppTest

    path = Path(__file__).resolve().parents[1] / "app.py"
    test_app = AppTest.from_file(str(path), default_timeout=15).run()
    assert len(test_app.exception) == 0, [str(x.message) for x in test_app.exception]
    assert any("MPushAgent Log Analyzer" in x.value for x in test_app.title)
    assert len(test_app.get("file_uploader")) == 1
    nav=next(x for x in test_app.radio if x.label=='업무 단계')
    assert nav.options==['1 자료 가져오기','2 분석 결과','3 문의·기록','4 내보내기']
    assert nav.value=='1 자료 가져오기'
    assert not any(x.label=='분석 작업 선택' for x in test_app.selectbox)
