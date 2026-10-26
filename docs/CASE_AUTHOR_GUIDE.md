# 별도 AI용 해결 사례 작성 규칙 (Stage 3 · v1.1 신호 목록)

Stage-1에서 이 규격을 고정합니다. 이 가이드와 knowledge/schema/case.schema.json,
knowledge/schema/signal_catalog.json을 반드시 먼저 읽고 사례당 JSON 파일 하나를 작성하세요.

## 작성 원칙
1. 근거가 없는 원인 확정, 해결 완료 판정을 하지 않습니다.
2. 실제 확인된 증상, 추정 원인, 근본 원인, 임시 조치, 해결 검증을 분리합니다.
3. AI가 생성한 초안은 반드시 status=investigating (또는 mitigated), review.state=draft, approved_at=null로 제출합니다.
   승인 상태나 resolved_verified는 AI가 임의로 지정하지 않습니다.
4. 원인·조치·해결이 실제 확인되었다면 초안에도 root_cause.status=confirmed,
   root_cause.evidence, resolution.actions, resolution.verified=true,
   verification.status=verified, verification.evidence 및 references를 정확히 작성합니다.
   담당자가 자료와 출처를 직접 검토하고 해결 완료를 별도 승인하면 그때 resolved_verified로 승격됩니다.
5. 신호 코드는 signal_catalog.json에 있는 코드만 사용합니다.
   추가 신호가 필요하면 JSON에 임의로 삽입하지 말고 별도 제안합니다.
6. 고객사 이름, 전화번호, IP/서버 주소, 메일주소, 비밀번호, 키, 메시지 내용, 원본 로그는
   포함하지 않습니다. 검색용 조건은 환경 특성과 비식별 신호만 사용합니다.
7. 출처 식별자는 가급적 민감정보가 제거된 레드마인 번호/테스트 문서 ID만 사용합니다.
8. 한번 발급한 case_id를 다른 사례에 재사용하지 않고 수정 시 revision을 증가시킵니다.
9. 검증 도구의 통과는 출처의 사실성이나 해결의 진위를 검증했다는 뜻이 아닙니다.
10. 결과물은 로컬 knowledge/inbox에 검토 대기로 전달하고, 담당자 검토 후만 승인합니다.

## 샘플
tests/fixtures/case_draft.json

## 검증
앱의 '해결 사례 관리' 탭에 JSON 파일을 업로드합니다.
검증을 통과하면 검토 대기함(inbox)에 등록할 수 있습니다.
담당자의 명시적 검토 승인을 거친 자료만 approved로 이동하여 매칭됩니다.
근본 원인과 조치·해결 증거가 불충분한 자료는 참고 사례로만 표시합니다.
승인된 기존 사례가 있더라도 새로운 고객사 장애의 원인과 동일하다고 확정하지 않습니다.
