"""Explicit navigation helpers for the v4.4 lazy workflow (tests only)."""
def open_analysis(app, *, advanced=False):
    app=next(x for x in app.radio if x.label=='업무 단계').set_value('2 분석 결과').run()
    if advanced:
        app=next(x for x in app.checkbox if x.label=='고급 분석 도구 열기').check().run()
    assert not app.exception,[e.message for e in app.exception]
    return app
