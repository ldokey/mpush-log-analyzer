/* Local-only adapter for actual Stitch desktop screens. No third-party runtime. */
'use strict';
(() => {
  const root = document.getElementById('root');
  const title = {overview:'핵심 요약',errors:'오류 원인',lookup:'메시지 검색',jobs:'Job·성능'};
  const statusLabels = {observed:'관측 기록',attention:'확인 필요',insufficient:'자료 부족',not_observed:'실행 미관측',original_success:'원 발송 성공',fallback_success:'문자 대체 성공',final_failure:'최종 실패 관측',original_failure_unresolved:'원 발송 실패·대체 미확인',accepted_unresolved:'요청 수락·결과 미확인',stage_failure_unresolved:'단계 실패·최종 미확인',conflict:'충돌·검토 필요',unknown:'결과 미확인',success:'성공 관측',failure:'실패 관측',unobserved:'미관측'};
  const stageLabels = {claim:'DB 선점',file:'파일 생성',tcp:'TCP 전송',accepted:'요청 수락',result:'결과 수신',db_transfer:'DB 이관'};
  const stageStates = {unobserved:'미관측',marker:'표지 관측',completed:'명시 완료',failed:'명시 실패',mixed:'혼재·확인 필요'};
  let args = {}, p = {}, revision = '', view = 'overview', selectedJob = '', selectedMessage = '', jobFilter = '', messageFilter = '', search = '', page = 0, jobPage = 0;
  const focusState={error:'',scope:'',lookupPage:0,lookupIndex:0};
  const expectedOrigin = (()=>{try{return new URL(document.referrer).origin}catch{return ''}})();
  const E = value => String(value ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const N = (value, digits=2) => value === null || value === undefined || !Number.isFinite(Number(value)) ? '—' : Number(value).toLocaleString('ko-KR',{maximumFractionDigits:digits});
  const T = v => v ? String(v).replace('T',' ').replace(/\.\d+(?=[+-])/,'').replace('+09:00','') : '미확인';
  const short = v => v ? v.replace('message_','MSG·').replace('service_','SVC·').slice(0,16) : '—';
  const button = (label,action,more='',primary=false) => `<button type="button" class="btn ${primary?'btn-primary':'btn-secondary'}" data-action="${action}" ${more}>${E(label)}</button>`;
  const chip = (state,label) => `<span class="chip ${E(state)}">${E(label||statusLabels[state]||state)}</span>`;
  const card = (name,value,unit,note,state='') => `<div class="kpi-card"><div class="kpi-header"><span class="kpi-title">${E(name)}</span>${state?chip(state):''}</div><div class="kpi-value-row"><span class="kpi-value mono">${E(value)}</span><span class="kpi-unit">${E(unit)}</span></div><div class="kpi-footer">${E(note)}</div></div>`;
  const panel = (heading,body,sub='') => `<section class="panel"><div class="panel-head"><span>${E(heading)}</span><span class="panel-sub">${E(sub)}</span></div>${body}</section>`;
  const empty = text => `<div class="empty">${E(text)}</div>`;
  function post(type,extra={}) { if(window.parent!==window) window.parent.postMessage({isStreamlitMessage:true,type,...extra},expectedOrigin||'*'); }
  function action(name,data={}) {post('streamlit:setComponentValue',{dataType:'json',value:{action:name,revision:p.revision,nonce:crypto.randomUUID(),...data}});}
  function frameHeight() {post('streamlit:setFrameHeight',{height:Math.min(4200,Math.max(420,root.scrollHeight+20))});}
  const refKey = r => `${r.file_id}:${r.line_start}:${r.line_end}:${r.occurred_at||''}`;
  function evidence(refs) {
    const unique = [...new Map((refs||[]).filter(Boolean).map(r=>[refKey(r),r])).values()];
    return unique.length ? `<div class="evidence-list">${unique.slice(0,8).map(r=>{
      const idx=(p.references||[]).findIndex(x=>refKey(x)===refKey(r));
      const local=args.local_labels?.[r.file_id]||r.file_id;
      return `<button type="button" class="evidence-link" data-action="evidence" data-index="${idx}" ${idx<0?'disabled':''}><span class="evidence-time">${E(T(r.occurred_at))}</span>${E(local)} · ${E(r.line_start)}–${E(r.line_end)}행 ↗</button>`;
    }).join('')}${unique.length>8?`<span class="muted">대표 8개 표시 / 근거 ${unique.length}개. 전체 수치는 요약에 보존합니다.</span>`:''}</div>` : `<p class="muted">연결할 원본 근거가 없습니다.</p>`;
  }
  function qualityBox(d) {
    const q=d.coverage||{}, last=(d.tails||[]).reduce((v,x)=>!v||x.last_observed>v?x.last_observed:v,null);
    const selected=(d.jobs||[]).find(x=>x.name===selectedJob);
    const values=[['기준 구간',d.baseline_window?'담당자 지정 · 동일 조건 확인':'지정하지 않음'],['완전성 제한',q.nonfull_files?.length?`${q.nonfull_files.length}개 파일`:'제공 자료 기준'],['미제공 로그',(q.missing_kinds||[]).join(', ')||'없음'],['주기 근거',selected?.cadence_seconds?`${N(selected.cadence_seconds)}초 · ${selected.cadence_basis==='baseline'?'기준 구간':'현재 관측'}`:'자료 부족'],['마지막 인식 기록',T(last)],['실제 수집 시각',T(q.collected_at)]];
    return `<aside class="evidence-quality-card panel-body" style="background:white;border:1px solid #e2e8f0;border-radius:6px"><div class="chart-title">자료 범위와 해석 한계</div>${values.map(([a,b])=>`<div class="quality-row"><span>${E(a)}</span><span>${E(b)}</span></div>`).join('')}<p class="footer-note">마지막 인식 기록은 원본의 최종 행이나 장애 발생 시각을 의미하지 않습니다.</p></aside>`;
  }
  function chart(job,performance=false) {
    if(!job?.current)return empty('조사 구간에는 선택 Job의 실행 기록이 없습니다. 기준 구간 수치를 현재 관측값으로 채우지 않습니다.');
    const before=job?.baseline?.buckets||[], current=job?.current?.buckets||before.map(b=>({...b,target_rate:null,duration_max:null})), key=performance?'target_rate':'duration_max';
    const values=current.map(x=>x[key]), base=performance?before.map(x=>x[key]):current.map(()=>job?.baseline?.duration?.p95??null);
    if(!values.some(v=>v!==null&&v!==undefined)&&!base.some(v=>v!==null&&v!==undefined)) return empty('선택 구간의 유효한 수치 기록이 없습니다. 미관측을 0으로 채우지 않습니다.');
    const max=Math.max(1,...values.filter(v=>v!=null),...base.filter(v=>v!=null))*1.12, w=760,h=210,left=52,right=18,top=15,bottom=32, span=h-top-bottom;
    const x=i=>left+i*(w-left-right)/Math.max(1,values.length-1), y=v=>h-bottom-v/max*span;
    let svg=`<svg class="chart-svg" viewBox="0 0 ${w} ${h}" role="img" aria-label="${performance?'관측 처리율':'Job 소요시간'} 추이">`;
    for(let i=0;i<4;i++){const val=max*i/3, yy=y(val);svg+=`<line x1="${left}" y1="${yy}" x2="${w-right}" y2="${yy}" stroke="#e2e8f0"/><text x="${left-9}" y="${yy+4}" text-anchor="end" font-size="10" fill="#64748b">${N(val,1)}</text>`;}
    if(!performance && p.jobs?.window?.seconds){const start=new Date(p.jobs.window.start).getTime(),seconds=p.jobs.window.seconds;for(const gap of job?.gaps||[]){const a=Math.max(0,(new Date(gap.start).getTime()-start)/1000),b=Math.min(seconds,(new Date(gap.end).getTime()-start)/1000);if(b>a)svg+=`<rect x="${left+a/seconds*(w-left-right)}" y="${top}" width="${(b-a)/seconds*(w-left-right)}" height="${span}" fill="#fef3c7" opacity=".7"/>`;}}
    function line(data,color,dashed){let segment=[];function flush(){if(segment.length>1)svg+=`<polyline points="${segment.join(' ')}" fill="none" stroke="${color}" stroke-width="2" ${dashed?'stroke-dasharray="5 4"':''}/>`;segment=[];}
      data.forEach((v,i)=>{if(v==null){flush();return;}segment.push(`${x(i)},${y(v)}`);if(!dashed)svg+=`<circle cx="${x(i)}" cy="${y(v)}" r="2.5" fill="${color}"/>`;});flush();}
    line(base,'#94a3b8',true);line(values,'#4338ca',false);
    for(const i of [...new Set([0,Math.floor(values.length/2),values.length-1])])if(current[i])svg+=`<text x="${x(i)}" y="${h-9}" text-anchor="middle" font-size="10" fill="#64748b">${E(current[i].at.slice(11,19))}</text>`;
    svg+='</svg>';
    return svg+`<div class="phase-caption">단위: ${performance?'대상 건/초':'초'} · 인디고: 조사 구간 ${performance?'관측 처리율':'버킷 최대 소요시간'} / 회색: ${performance?'동일 경과시간 기준 구간':'기준 구간 P95'} · 빈 구간은 미관측</div>`;
  }
  function jobTable(rows,performance=false) {
    const count=Math.ceil(rows.length/15);jobPage=Math.min(jobPage,Math.max(0,count-1));
    const cols=performance?['Job','기록','대상 합계','평균 / P50','P95 / 최대','기준 P95 배율','구간 대상/초','실행 대상/초','최장 관측 단계']:['상태','Job','기준 P95','조사 P95','P95 배율','RUNNING','ABNORMAL','공백','지연 기록'];
    const body=rows.slice(jobPage*15,(jobPage+1)*15).map(r=>{const c=r.current,b=r.baseline;
      const name=`<button class="row-link" type="button" data-action="job" data-job="${E(r.name)}">${E(r.name)}</button>`;
      const cells=performance?[name,N(c?.records,0),N(c?.targets,0),`${N(c?.duration?.mean)} / ${N(c?.duration?.p50)}`,`${N(c?.duration?.p95)} / ${N(c?.duration?.max)}`,N(r.p95_ratio)+'×',N(c?.window_target_rate),N(c?.execution_target_rate),E(c?.longest_observed_stage?.toUpperCase()||'미관측')]:[chip(r.status),name,N(b?.duration?.p95),N(c?.duration?.p95),N(r.p95_ratio)+'×',N(c?.running_skips,0),N(c?.abnormal_skips||0,0),N(c&&r.gap_evaluated_streams&&!r.sequence_records_omitted?r.gap_count:null,0),N(c?.delay_count,0)];
      return `<tr class="${r.name===selectedJob?'selected-row':''}">${cells.map(c=>`<td>${c}</td>`).join('')}</tr>`;
    }).join('');
    return `<div class="scroll-table"><table class="data-table"><thead><tr>${cols.map(c=>`<th>${E(c)}</th>`).join('')}</tr></thead><tbody>${body||`<tr><td colspan="${cols.length}">${empty('해당 조건의 Job 기록이 없습니다.')}</td></tr>`}</tbody></table></div><div class="pagination">${button('이전','job-prev',jobPage===0?'disabled':'')}<span class="muted">${N(jobPage+1,0)} / ${N(Math.max(1,count),0)} · ${N(rows.length,0)}개 Job</span>${button('다음','job-next',jobPage>=count-1?'disabled':'')}</div>`;
  }
  function jobDetail(j,performance=false) {
    if(!j)return empty('조사할 Job을 선택해 주세요.');
    const c=j.current, duration=c?.duration;
    const facts=performance?[`작업대상 표본 ${N(c?.target_samples,0)}개 · 실행시간 짝 표본 ${N(c?.paired_samples,0)}개`, `동일 짝 대상 ${N(c?.paired_targets,0)}건 / 실행시간 ${N(c?.paired_seconds)}초`, `가장 긴 관측 단계: ${c?.longest_observed_stage?.toUpperCase()||'미관측'}`]:[`관측 공백 ${N(c&&j.gap_evaluated_streams&&!j.sequence_records_omitted?j.gap_count:null,0)}구간 · RUNNING 반복군 ${N(c?j.running_cluster_count:null,0)}개`, `지연 기록 ${N(c?.delay_count,0)}회 · ${c?.delay_basis==='baseline_p95'?'기준 P95 대비':'정상 기준 없음/부족: 절대 시간 기준'}`,`소요시간 표본 ${N(duration?.samples,0)}개${duration?.percentiles_unavailable?' · 상한으로 백분위 보류':''}`];
    if(j.tail_observation&&!performance)facts.push(`마지막 완료 이후 ${N(j.tail_observation.seconds)}초 후속 완료 미관측${j.tail_observation.full_sources?'':' · 부분 자료: 판정 보류'}. 입력 수집시각/조사 종료 기준이며 종료 확정 아님.`);
    if(c?.abnormal_skips)facts.push(`ABNORMAL 상태로 실행 건너뜀 ${N(c.abnormal_skips,0)}회. RUNNING 반복과 별도 관측입니다.`);
    const gap=j.gaps?.[0];if(gap&&!performance)facts.push(`${T(gap.start)} → ${T(gap.end)}: ${N(gap.seconds)}초 공백 (기준 ${N(gap.threshold)}초)`);
    const cluster=j.running_clusters?.[0];if(cluster&&!performance)facts.push(`반복군 ${T(cluster.start)}~${T(cluster.end)} · ${cluster.count}회`);
    const refs=[...(c?.delays||[]).map(x=>x.ref),...(j.gaps||[]).flatMap(x=>[x.before_ref,x.after_ref]),...(j.running_clusters||[]).flatMap(x=>x.refs),...(j.tail_observation?[j.tail_observation.ref]:[]),...(c?.evidence||[])];
    return panel(`선택 Job 근거 · ${j.name}`,`<div class="detail-grid"><section class="detail-box"><div class="detail-box-title">관측 사실</div>${facts.map(s=>`<p>${E(s)}</p>`).join('')}${j.sequence_records_omitted?`<p class="warning">순서 분석 ${N(j.sequence_records_omitted,0)}개 생략: 공백·반복군 판정 보류</p>`:''}</section><section class="detail-box limit-box"><div class="detail-box-title">해석 한계</div><p>${E(performance?p.jobs.performance_note:p.jobs.note)}</p><p>단계 시간은 중첩되거나 표본 수가 다를 수 있습니다. 단일 병목 원인으로 확정하지 않습니다.</p></section><section class="detail-box"><div class="detail-box-title">원본 근거</div>${evidence(refs)}</section></div>`);
  }
  function jobsPage(){const d=p.jobs||{},all=d.jobs||[],rows=jobFilter?all.filter(x=>x.name===jobFilter):all,j=all.find(x=>x.name===selectedJob),curr=rows.filter(x=>x.current);
    const sum=f=>curr.length?curr.reduce((n,r)=>n+f(r),0):null;
    return `<div class="section-header"><h2 class="section-title">Job 실행 진단</h2><span class="amber-note">기록 공백은 Agent 종료를 의미하지 않습니다</span></div><div class="kpi-grid">${card('Job 실행 기록',N(sum(x=>x.current.records),0),'회','고유 메시지 수가 아닌 실행 기록')}${card('관측 공백',N(curr.some(x=>x.gap_evaluated_streams&&!x.sequence_records_omitted)?curr.filter(x=>x.gap_evaluated_streams&&!x.sequence_records_omitted).reduce((n,x)=>n+x.gap_count,0):null,0),'구간','기준 간격 대비 · 파일 경계 제외')}${card('RUNNING 건너뜀',N(sum(x=>x.current.running_skips),0),'회','반복군과 개별 기록을 구분')}${card('급증·절대 지연',N(sum(x=>x.current.delay_count),0),'회',`기준 P95×${N(d.policy?.spike_ratio)} / 최소 ${N(d.policy?.absolute_delay_seconds)}초`)}</div><div class="chart-row"><section class="chart-card"><div class="chart-card-header"><span class="chart-title">선택 Job 소요시간 추이</span><span class="muted">${E(selectedJob||'선택 없음')}</span></div>${chart(j)}</section>${qualityBox(d)}</div>${panel('Job 실행 진단표',jobTable(rows),'행을 선택하면 추이·근거를 함께 표시합니다')}${jobDetail(j)}${panel('다음 확인사항',`<div class="panel-body facts-list">동일 시간대 DB·네트워크 오류와 Job 완료 기록을 대조하세요.<br>RUNNING 반복만으로 프로세스 정지를 판단하지 말고 담당자가 확인한 PID·스레드 상태와 수집 범위를 확인하세요.<br><span class="mono">ps -eo pid,etime,args | grep '[M]Push'</span><p class="muted">읽기 전용 명령 예시입니다. 이 프로그램은 명령을 실행하지 않습니다.</p></div>`)}`;
  }
  function messageDetail(g){if(!g)return empty('메시지를 선택해 근거를 확인하세요.');const events=(g.event_indexes||[]).map(i=>p.messages.events[i]).filter(Boolean).sort((a,b)=>a.ref.occurred_at.localeCompare(b.ref.occurred_at));
    const leg=(label,field,v)=>`<div class="outcome-card"><div class="outcome-title">${E(label)}</div><div class="outcome-code">${E(field)}</div>${chip(v.state)}<div class="outcome-code">${E(v.codes.join(' / ')||'결과 코드 미관측')}</div></div>`;
    return `<div class="detail-container">${panel('선택 메시지 · '+short(g.message),`<div class="panel-body">${chip(g.status,g.status_label)}<div class="journey">${Object.entries(stageLabels).map(([k,label])=>`<div class="stage-node"><div class="stage-badge ${E(g.stages[k])}">${g.stages[k]==='unobserved'?'—':g.stages[k]==='failed'?'!':'●'}</div><div class="stage-name">${E(label)}</div><div class="stage-state">${E(stageStates[g.stages[k]])}</div></div>`).join('')}</div><div class="outcome-pair">${leg('원 발송','SEND_RESULT_CODE1',g.primary)}${leg('문자 대체','SEND_RESULT_CODE2',g.fallback)}</div><p class="footer-note">요청→결과 관측 간격: <strong>${g.request_to_result_seconds===null?'계산 보류 (유일한 요청·결과 쌍 없음)':N(g.request_to_result_seconds)+'초'}</strong></p><p class="muted">원문 기록 ${g.records}건 / 결과 수신 ${g.result_observations}건 · 반복 결과를 메시지 수로 더하지 않습니다.</p></div>`)}${panel('근거 이력',`<div class="panel-body">${events.slice(0,8).map(ev=>`<div class="quality-row"><span>${chip(ev.basis,ev.basis==='sql_excluded'?'SQL 조건 · 판정 제외':ev.basis==='result_received'?'결과 수신 근거':'단계 표지')}</span><span>${E(T(ev.ref.occurred_at))}</span></div>`).join('')}${evidence(g.evidence)}${g.evidence_omitted?`<p class="muted">근거 상세 ${g.evidence_omitted}개 생략. 결과 상태 집계는 유지됩니다.</p>`:''}</div>`)}${panel('관측 사실 · 해석 한계 · 추가 확인',`<div class="panel-body facts-list"><p>${E(g.status_label)}. 원 발송과 문자 대체 결과를 각각 확인하세요.</p><p>미관측 단계는 실패가 아닙니다. 성공/실패 코드는 결과 수신 필드에서만 판정하며 사유를 임의로 매핑하지 않습니다.</p><p>상반 결과나 재시도가 있으면 결과 테이블·추가 수집 로그로 확인하세요. 이 화면은 실제 재발송이나 DB 조작을 하지 않습니다.</p></div>`)}</div>`;
  }
  function messagesPage(){const m=p.messages;
    if(!m)return `<h2 class="section-title">메시지 결과 추적</h2><div class="warning">원본을 다시 읽는 기능입니다. 명시적인 조회 동의 후 실행하며 외부 전송은 하지 않습니다.</div>${panel('메시지 근거 조회',empty('아직 원본 조회를 실행하지 않았습니다. 아래 버튼에서 서비스/메시지 검색과 조회 동의를 설정하세요.')+`<div class="panel-body">${button('원본 조회 조건 열기','configure-messages','',true)}</div>`)}`;
    const sum=m.summary;let groups=m.groups.filter(g=>(!messageFilter||g.status===messageFilter)&&(!search||(g.message+' '+g.service).toLowerCase().includes(search.toLowerCase())));groups=[...groups].sort((a,b)=>b.last.localeCompare(a.last));const pages=Math.ceil(groups.length/25);page=Math.min(page,Math.max(0,pages-1));if(!groups.some(g=>g.message===selectedMessage))selectedMessage=groups[0]?.message||'';const chosen=groups.find(g=>g.message===selectedMessage);
    const states=[...new Set(m.groups.map(g=>g.status))];
    return `<div class="section-header"><h2 class="section-title">메시지 결과 추적</h2>${button('원본 조회 조건','configure-messages')}</div><div class="warning">요청 수락(RESPONSE_CODE=S)과 최종 발송 결과는 다릅니다. 원 발송과 문자 대체발송을 분리합니다.</div><div class="kpi-grid">${card('결과 성공 관측',N(sum.success,0),'건',`판정 가능 ${N(sum.classifiable_messages,0)}건 중 ${N(sum.observed_success_percent)}%`)}${card('최종 실패 관측',N(sum.failure,0),'건','양쪽 실패 또는 명시적 대체 없음')}${card('결과 미확인',N(sum.unresolved,0),'건','수락만 관측 · 대체 미확인 포함')}${card('결과 충돌',N(sum.conflict,0),'건','상반 결과를 마지막 값으로 덮지 않음')}</div><p class="footer-note">조회 조건에 일치한 고유 메시지 ${N(sum.unique_messages,0)}건. 성공률은 이 중 결과 판정 가능한 메시지만 분모에 포함하며 전체 발송 성공률이 아닙니다.</p>${(m.empty_reasons||[]).map(t=>`<div class="warning">${E(t)}</div>`).join('')}${m.population_limited?'<div class="warning">메시지 상한으로 일부 식별값이 제외됐습니다. 조회 구간/식별값을 좁혀 주세요.</div>':''}<div class="top-tools"><label>상태 <select id="message-status" class="filter-select"><option value="">전체 상태</option>${states.map(s=>`<option value="${E(s)}" ${s===messageFilter?'selected':''}>${E(statusLabels[s])}</option>`).join('')}</select></label><label>가명 검색 <input id="message-search" class="filter-input" value="${E(search)}" placeholder="가명 메시지 또는 가명 서비스"></label>${button('검색 적용','search')}<span class="muted">원문 MESSAGE_SEQNO 검색은 ‘원본 조회 조건’에서 실행합니다.</span></div><div class="workspace-split">${panel('관측 메시지',`<div class="scroll-table"><table class="msg-table"><thead><tr>${['메시지 / 서비스 가명','원 발송','문자 대체','현재 판정'].map(x=>`<th>${E(x)}</th>`).join('')}</tr></thead><tbody>${groups.slice(page*25,(page+1)*25).map(g=>`<tr class="${g.message===selectedMessage?'selected-row':''}"><td><button class="row-link" type="button" data-action="message" data-message="${E(g.message)}" title="${E(g.message)}">${E(short(g.message))}</button><div class="muted" title="${E(g.service)}">${E(short(g.service))}</div></td><td>${chip(g.primary.state)}</td><td>${chip(g.fallback.state)}</td><td>${chip(g.status,g.status_label)}</td></tr>`).join('')||'<tr><td colspan="4">'+empty('일치하는 메시지가 없습니다.')+'</td></tr>'}</tbody></table></div><div class="pagination">${button('이전','message-prev',page===0?'disabled':'')}<span class="muted">${page+1} / ${Math.max(1,pages)} · ${groups.length}건</span>${button('다음','message-next',page>=pages-1?'disabled':'')}</div>`, '25건씩 조회')}${messageDetail(chosen)}</div>${panel('조회 품질',`<div class="panel-body facts-list">${Object.entries(m.coverage).filter(([k])=>['total_records','undated_records','outside_window_records','search_excluded_records','candidate_records','missing_identity_records','ambiguous_or_payload_records','oversized_records','sql_predicate_records','event_details_omitted','message_limit_records'].includes(k)).map(([k,v])=>`<span class="chip">${E(({total_records:'전체 레코드',undated_records:'날짜 없음 제외',outside_window_records:'조회 구간 밖',search_excluded_records:'검색 조건 제외',candidate_records:'식별 후보',missing_identity_records:'식별값 부족',ambiguous_or_payload_records:'모호/본문 포함 제외',oversized_records:'과대 레코드 제외',sql_predicate_records:'SQL 판정 제외',event_details_omitted:'상세 표시 생략',message_limit_records:'메시지 상한 제외'})[k])}: ${N(v,0)}</span> `).join('')}<p class="footer-note">${E(m.note)}</p></div>`)}`;
  }
  function backlogPanel(){const b=p.backlog||{rows:[],latest:null};return panel('대기량 관측',`<div class="backlog-form"><label>관측 시각 (KST)<input id="backlog-time" class="filter-input" type="datetime-local" step="1"></label><label>대기 건수<input id="backlog-count" class="filter-input" type="number" min="0" max="1000000000" step="1" style="width:135px"></label><label><input id="backlog-confirm" type="checkbox" ${b.comparable?'checked':''}> 모든 관측값의 동일 서비스·조회 조건 확인</label>${button('관측값 등록','backlog-add','',true)}</div><p class="muted" style="padding:0 16px 12px">담당자 입력 · 현재 브라우저 세션 한정 · DB 자동 조회 없음. 새로고침/세션 종료 전 필요한 요약을 저장하세요.</p>${b.rows.length?`<div class="scroll-table"><table class="data-table"><thead><tr><th>관측 시각</th><th>대기 건수</th><th>직전 대비 순증감</th><th>순증감 / 초</th></tr></thead><tbody>${b.rows.map(r=>`<tr><td>${E(T(r.at))}</td><td>${N(r.count,0)}</td><td>${N(r.change,0)}</td><td>${N(r.net_change_per_second)}</td></tr>`).join('')}</tbody></table></div>`:empty('로그만으로 DB 대기량을 확정할 수 없습니다. 담당자가 확인한 숫자 관측값을 입력하세요.')}<div class="panel-body muted">${E(b.note||'순증감은 실제 처리속도·유입률·해소 ETA가 아닙니다.')}</div>`,'입력 자료는 자동 저장/외부 전송하지 않습니다');}
  function performancePage(){const d=p.jobs||{},all=d.jobs||[],rows=jobFilter?all.filter(x=>x.name===jobFilter):all,j=all.find(x=>x.name===selectedJob),c=j?.current,steps=c?.steps||{},max=Math.max(1,...Object.values(steps).map(x=>x.mean));
    const bars=Object.entries(steps).map(([name,x])=>`<div class="bar-row"><span>${E(name.toUpperCase())}</span><div class="bar-track"><div class="bar-fill" style="width:${x.mean/max*100}%"></div></div><span>${N(x.mean)}초</span></div><p class="muted">${N(x.samples,0)}개 표본 · 기준 ${N(j?.baseline?.steps?.[name]?.mean)}초</p>`).join('');
    return `<div class="section-header"><h2 class="section-title">처리 성능·대기량</h2><span class="muted">KPI·차트: ${E(selectedJob||'Job 선택 필요')}</span></div><div class="warning">로그의 작업대상 건수는 성공 건수나 현재 DB 적체량이 아닙니다. 서로 다른 Job의 대상 건수를 고유 메시지 수로 합산하지 않습니다.</div><div class="kpi-grid">${card('선택 Job 작업대상 합계',N(c?.targets,0),'건',`대상 필드가 있는 완료기록 ${N(c?.target_samples,0)}개`)}${card('구간 관측 처리율',N(c?.window_target_rate),'대상/초',`전체 조사 구간 ${N(d.window?.seconds,0)}초 기준`)}${card('실행시간 기준 처리율',N(c?.execution_target_rate),'대상/초',`유효한 동일 짝 ${N(c?.paired_samples,0)}개 기준`)}${card('DB 대기량 관측',N(p.backlog?.latest,0),'건',p.backlog?.latest==null?'자료 없음 · 담당자 관측값 필요':'담당자 입력 · 로그 추정 아님')}</div><div class="chart-row"><section class="chart-card"><div class="chart-title">시간대별 관측 처리율 · 실제 ${N(d.bucket_seconds,0)}초 버킷</div>${chart(j,true)}</section><section class="chart-card"><div class="chart-title">단계별 평균 소요시간</div>${bars||empty('단계 시간 자료가 없습니다.')}<p class="footer-note">단계는 중첩될 수 있습니다. 막대 합계를 전체 소요시간이나 병목 원인으로 해석하지 마세요.</p></section></div>${panel('Job별 처리 성능',jobTable(rows,true),'단위: 초 / 대상 건수 · 평균 TPS가 아닌 합계 비율')}${backlogPanel()}${jobDetail(j,true)}`;
  }
  function render(){
    const d=p.jobs||{},jobs=d.jobs||[];
    if(!p.focus&&view==='overview')view='jobs';
    if(!jobs.some(x=>x.name===selectedJob))selectedJob=jobs.find(x=>x.status==='attention')?.name||jobs[0]?.name||'';
    document.getElementById('stitch-style').textContent=window.MPUSH_STITCH.jobs.css;
    const focused=window.MPUSH_FOCUS_VIEWS({p,E,N,T,chip,panel,empty,evidence,button,state:focusState});
    const active=(view==='performance'?'jobs':view);
    const nav=`<nav class="secondary-tabs focus-nav" aria-label="분석 결과 화면">${Object.entries(title).map(([key,label])=>`<button type="button" class="sub-tab nav-tab ${key===active?'active':''}" data-action="tab" data-view="${key}" aria-current="${key===active?'page':'false'}">${E(label)}</button>`).join('')}</nav>`;
    const context=`<div class="context-row"><div class="scope-info"><span class="scope-tag">단일 Agent</span><span class="time-range">${E(T(d.window?.start))} → ${E(T(d.window?.end))} KST</span></div><div class="context-actions">${button('조사 구간','configure')}${button('자료 점검','input-quality')}${button('비식별 요약','export')}</div></div>`;
    const jobtools=(view==='jobs'||view==='performance')?`<div class="top-tools">${button('실행 진단','tab','data-view="jobs"',view==='jobs')}${button('처리 성능·대기량','tab','data-view="performance"',view==='performance')}<label>Job <select id="job-filter" class="filter-select"><option value="">전체 Job</option>${jobs.map(j=>`<option value="${E(j.name)}" ${j.name===jobFilter?'selected':''}>${E(j.name)}</option>`).join('')}</select></label></div>`:'';
    const content=view==='overview'?focused.overview():view==='errors'?focused.errors():view==='lookup'?focused.lookup():view==='performance'?performancePage():jobsPage();
    const warnings=d.warnings||[];
    root.innerHTML=nav+context+`<main class="content-area">${jobtools}${content}${warnings.length?`<details class="panel"><summary class="panel-head">자료 범위·판단 한계 ${warnings.length}개</summary><div class="panel-body">${warnings.map(w=>`<p class="footer-note">${E(w)}</p>`).join('')}${button('자료 점검 열기','input-quality')}</div></details>`:''}<footer class="footer-note">V4.4 · 원본 보존 · 자동 운영 조치 없음 · 검색 결과와 최종 발송 결과를 구분합니다.</footer></main>`;
    requestAnimationFrame(frameHeight);
  }
  root.addEventListener('toggle',frameHeight,true);
  root.addEventListener('change',e=>{if(e.target.id==='lookup-scope'){focusState.scope=e.target.value;focusState.lookupPage=0;focusState.lookupIndex=0;render();}if(e.target.id==='job-filter'){jobFilter=e.target.value;jobPage=0;if(jobFilter)selectedJob=jobFilter;render();}if(e.target.id==='message-status'){messageFilter=e.target.value;page=0;render();}});
  root.addEventListener('keydown',e=>{if(e.target.id==='message-search'&&e.key==='Enter'){search=e.target.value;page=0;render();}});
  root.addEventListener('click',e=>{const b=e.target.closest('button[data-action]');if(!b||b.disabled)return;
    switch(b.dataset.action){
      case'tab':view=b.dataset.view;render();break;
      case'focus-error':focusState.error=b.dataset.error;view='errors';render();break;
      case'focus-select-error':focusState.error=b.dataset.error;render();break;
      case'focus-lookup':view='lookup';render();break;
      case'lookup-row':focusState.lookupIndex=Number(b.dataset.index);render();break;
      case'lookup-prev':focusState.lookupPage--;render();break;
      case'lookup-next':focusState.lookupPage++;render();break;
      case'all-evidence':action('all_evidence');break;
      case'input-quality':action('input_quality');break;
      case'job':selectedJob=b.dataset.job;render();break;
      case'message':selectedMessage=b.dataset.message;render();break;
      case'job-prev':jobPage--;render();break;case'job-next':jobPage++;render();break;
      case'message-prev':page--;render();break;case'message-next':page++;render();break;
      case'search':search=document.getElementById('message-search').value;page=0;render();break;
      case'evidence':action('evidence',{index:Number(b.dataset.index)});break;
      case'configure':action('configure');break;
      case'configure-messages':action('configure_messages');break;
      case'backlog-add':{const at=document.getElementById('backlog-time').value,raw=document.getElementById('backlog-count').value,count=Number(raw),comparable=document.getElementById('backlog-confirm').checked;if(!at||raw===''||!Number.isSafeInteger(count)||count<0||count>1e9){window.alert('관측 시각과 0~10억 정수 건수를 입력하세요.');return;}action('backlog',{at,count,comparable});break;}
      case'export':{const safe={schema:'mpush.investigation.v4.4',jobs:p.jobs,messages:p.messages,backlog:p.backlog,focus:p.focus,lookup:p.lookup,notice:'관측 자료 범위 한정. 원본명·식별값·본문·SQL 미포함.'};const url=URL.createObjectURL(new Blob([JSON.stringify(safe,null,2)],{type:'application/json;charset=utf-8'}));const a=document.createElement('a');a.href=url;a.download='mpush-investigation-v4.4.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);break;}
    }
  });
  function receive(next){const incoming=next.payload||{};if(revision&&revision===incoming.revision&&JSON.stringify(args.local_labels||{})===JSON.stringify(next.local_labels||{})){args=next;return;}const scopeChanged=p.input_scope!==incoming.input_scope;args=next;p=incoming;if(revision!==p.revision){focusState.lookupPage=0;focusState.lookupIndex=0;if(scopeChanged){focusState.scope='';focusState.error='';}revision=p.revision;selectedMessage='';page=0;const names=new Set((p.jobs?.jobs||[]).map(x=>x.name));if(scopeChanged||!names.has(jobFilter)){jobFilter='';selectedJob='';jobPage=0;}const groups=p.messages?.groups||[];if(scopeChanged||!groups.some(g=>g.status===messageFilter))messageFilter='';if(scopeChanged||(search&&!groups.some(g=>(g.message+' '+g.service).toLowerCase().includes(search.toLowerCase()))))search='';}render();}
  window.addEventListener('message',e=>{if(e.source!==window.parent||expectedOrigin&&e.origin!==expectedOrigin)return;if(e.data?.type==='streamlit:render')receive(e.data.args||{});});
  window.addEventListener('resize',frameHeight);
  // The deterministic standalone harness is useful for isolated synthetic browser tests.
  window.renderDiagnostics=receive;
  post('streamlit:componentReady',{apiVersion:1});post('streamlit:setFrameHeight',{height:420});
})();
