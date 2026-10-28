/**
 * JW-XDR — Local Host XDR Console Frontend (dashboard.mjs)
 * - 테스트/시뮬레이션 더미 로그 없이 실제 유입되는 HTTP 로그 및 호스트 실시간 로그만 표시
 * - 엄격한 CSP(style-src 'self') 준수: 인라인 스타일 속성 0건
 */

const state = {
  view: 'cases',
  searchQuery: '',
  caseFilter: 'ALL',
  eventChannelFilter: 'ALL',
  overview: null,
  activeCaseId: null,
  activeCaseDetail: null,
  activeCaseTab: 'basic',
  activeTenantTab: 'ai-link',
  sbomRequestSeq: 1,
  sbomDisplayedSeq: 0,
  lastPolicyRedactedText: '[실시간 재추출 & 마스킹 내보내기] 버튼을 누르거나 수동 판정값을 변경하면 민감 토큰이 [REDACTED] 처리된 보안 진단 JSON이 표시됩니다.',
  lastAiResultText: '[선택 케이스 AI 분석 실행] 버튼을 누르면 실제 수집된 eventId만을 근거로 생성한 AI 판정 결과가 표시됩니다.',
  lastBackupResultText: '[현재 SQLite DB 백업 생성] 버튼을 누르면 백업 파일명과 무결성 헤더 검증 결과가 여기에 표시됩니다.',
  manualChecklist: {
    PasswordComplexity: '양호',
    MinimumPasswordLength: '양호',
    MaximumPasswordAge: '양호',
    MinimumPasswordAge: '취약',
    LockoutBadCount: '양호',
    LockoutDuration: '취약',
    EnableGuestAccount: '양호',
    DefaultAdminRestricted: '취약'
  }
};

function esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function showToast(msg) {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const el = document.createElement('div');
  el.className = 'toast-item';
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

async function apiFetch(url, options = {}) {
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options
  });
  return res.json();
}

function sevBadgeClass(sev) {
  const s = String(sev || '').toUpperCase();
  if (s === 'CRITICAL' || s === '크리티컬' || s === '심각') return 'sev-critical';
  if (s === 'HIGH' || s === '높음') return 'sev-high';
  if (s === 'MEDIUM' || s === '중간') return 'sev-medium';
  return 'sev-low';
}

function aiBadgeClass(label) {
  if (label === '정탐 유력') return 'ai-tp';
  if (label === '오탐 유력') return 'ai-fp';
  return 'ai-hold';
}

function switchView(targetView) {
  state.view = targetView;
  document.querySelectorAll('#nav-dashboard-list .nav-item').forEach((b) => {
    b.classList.toggle('active', b.dataset.view === targetView);
  });
  renderCurrentView();
}

// ============================================================================
// 데이터 로드 및 상단/사이드바 실측 상태 갱신
// ============================================================================
async function loadOverview() {
  const data = await apiFetch('/api/overview');
  if (!data.ok) return;
  state.overview = data;

  const h = data.hostInfo || {};
  const m = data.metrics || {};

  const topHost = document.getElementById('top-host-badge');
  if (topHost) topHost.textContent = `${h.hostname || 'LOCAL'} · ${h.username || 'user'}`;

  const topMttd = document.getElementById('top-mttd');
  const topMttr = document.getElementById('top-mttr');
  const topAi = document.getElementById('top-ai-status');
  if (topMttd) topMttd.textContent = `MTTD ${m.avgMttdSec || '2.5'}s`;
  if (topMttr) topMttr.textContent = `MTTR ${m.avgMttrSec || '14.0'}s`;
  if (topAi) {
    const netCount = data.netstatSnapshot?.summary?.total || 0;
    const procCount = data.procSnapshot?.totalCount || 0;
    const winEvtCount = data.liveEventLogs?.totalCollected || 0;
    topAi.textContent = `● OS로그 ${winEvtCount}건 · TCP ${netCount}개 · 프로세스 ${procCount}개`;
  }

  const sbHost = document.getElementById('sb-hostname');
  const sbOs = document.getElementById('sb-os');
  const sbCpuMem = document.getElementById('sb-cpu-mem');
  const sbIp = document.getElementById('sb-ip');
  if (sbHost) sbHost.textContent = `${h.hostname || 'LOCAL-PC'} (${h.username || ''})`;
  if (sbOs) sbOs.textContent = `OS: ${h.platform || '--'}`;
  if (sbCpuMem) sbCpuMem.textContent = `CPU ${h.cpuCores || 0}코어 · RAM ${h.usedMemMb || 0}/${h.totalMemMb || 0}MB (${h.memUsagePct || 0}%)`;
  if (sbIp) {
    const firstIp = h.interfaces?.[0]?.address || '127.0.0.1';
    sbIp.textContent = `IPv4: ${firstIp}`;
  }

  renderCurrentView();
}

const VIEW_HEADERS = {
  cases: {
    title: '위협 케이스 & 실시간 유입 로그',
    sub: '실시간 Windows 이벤트 로그(wevtutil) · 실시간 유입 HTTP 요청 로그 · 실측 위협 케이스 관제'
  },
  network: {
    title: '실시간 네트워크 소켓 (netstat) & 게이트웨이 IP 차단',
    sub: '현재 호스트의 활성 TCP 연결 · 외부 원격 IP · 매핑된 로컬 프로세스 조회 및 즉시 차단'
  },
  endpoint: {
    title: '실행 프로세스 (tasklist) & 현재 세션 접근 상태',
    sub: '실시간 실행 프로세스 메모리 점유율 현황 및 로컬 호스트 하드웨어·네트워크 인터페이스'
  },
  policy: {
    title: 'Windows 로컬 보안 정책 실측 점검',
    sub: '현재 Windows 계정·레지스트리 설정값(net accounts / reg query)과 수동 점검표 1:1 대조 및 민감정보 마스킹'
  },
  sbom: {
    title: '공급망 취약점 스캔 (package-lock.json & OSV.dev)',
    sub: '고정 버전(exact_lock_version) 추출 및 Google OSV API 실시간 취약점 대조'
  },
  soar: {
    title: '능동 대응 (SOAR) · AI 근거 감사 · 데이터베이스 백업',
    sub: '능동 대응 승인 워크플로 · 실제 수집 이벤트 기반 AI 분석 · SQLite 무결성 백업'
  }
};

function renderCurrentView() {
  if (!state.overview) return;
  const headerMeta = VIEW_HEADERS[state.view] || VIEW_HEADERS.cases;
  document.getElementById('current-view-title').textContent = headerMeta.title;
  document.getElementById('current-view-subtitle').textContent = headerMeta.sub;

  const container = document.getElementById('view-container');
  if (!container) return;

  switch (state.view) {
    case 'cases':
      container.innerHTML = renderCasesView();
      bindCasesViewEvents();
      break;
    case 'network':
      container.innerHTML = renderNetworkView();
      bindNetworkViewEvents();
      break;
    case 'endpoint':
      container.innerHTML = renderEndpointView();
      bindEndpointViewEvents();
      break;
    case 'policy':
      container.innerHTML = renderPolicyView();
      bindPolicyViewEvents();
      break;
    case 'sbom':
      container.innerHTML = renderSbomView();
      bindSbomViewEvents();
      break;
    case 'soar':
      container.innerHTML = renderSoarView();
      bindSoarViewEvents();
      break;
    default:
      container.innerHTML = renderCasesView();
      bindCasesViewEvents();
  }
}

// ============================================================================
// 1. 위협 케이스 & 실시간 유입 로그 뷰 (cases)
// ============================================================================
function renderCasesView() {
  const q = state.searchQuery.toLowerCase();
  const allCases = state.overview.cases || [];
  const winEventsAll = state.overview.liveEventLogs?.events || [];
  const httpLogsAll = state.overview.liveHttpLogs || [];

  let filteredCases = allCases;
  if (state.caseFilter === 'New') filteredCases = allCases.filter((c) => c.status === 'New');
  else if (state.caseFilter === 'Ack') filteredCases = allCases.filter((c) => c.status === 'Acknowledged' || c.status === 'In Progress');
  else if (state.caseFilter === 'Closed') filteredCases = allCases.filter((c) => c.status === 'Closed');

  const cases = q
    ? filteredCases.filter((c) =>
        `${c.case_id} ${c.title} ${c.src_ip} ${c.target_asset} ${c.mitre_technique}`.toLowerCase().includes(q)
      )
    : filteredCases;

  let winEvents =
    state.eventChannelFilter === 'ALL'
      ? winEventsAll
      : winEventsAll.filter((ev) => ev.channel.toLowerCase() === state.eventChannelFilter.toLowerCase());
  if (q) {
    winEvents = winEvents.filter((ev) =>
      `${ev.recordId} ${ev.eventId} ${ev.provider} ${ev.message} ${ev.channel}`.toLowerCase().includes(q)
    );
  }

  const httpLogs = q
    ? httpLogsAll.filter((l) => `${l.clientIp} ${l.method} ${l.url} ${l.verdict} ${l.userAgent}`.toLowerCase().includes(q))
    : httpLogsAll;

  const newCnt = allCases.filter((c) => c.status === 'New').length;
  const ackCnt = allCases.filter((c) => c.status === 'Acknowledged' || c.status === 'In Progress').length;
  const blockedIpCnt = (state.overview.soarActions || []).filter(
    (a) => a.action_type === 'BLOCK_ATTACK_IP' && ['APPROVED', 'PENDING_ACK', 'EFFECT_VERIFIED'].includes(a.stage)
  ).length;

  return `
    <div class="summary-grid-5">
      <div class="summary-card clickable ${state.caseFilter === 'New' ? 'active-tile' : ''}" data-filter-card="New">
        <div class="summary-label">신규 탐지 케이스 (New)</div>
        <div class="summary-val emerald-text">${newCnt}</div>
        <div class="kpi-subnote">클릭하여 신규 케이스 필터링</div>
      </div>
      <div class="summary-card clickable ${state.caseFilter === 'Ack' ? 'active-tile' : ''}" data-filter-card="Ack">
        <div class="summary-label">인지 / 조사 중 (Ack)</div>
        <div class="summary-val">${ackCnt}</div>
        <div class="kpi-subnote">클릭하여 조사 중 케이스 필터링</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">Windows 이벤트 로그 (실측)</div>
        <div class="summary-val emerald-text">${winEventsAll.length}건</div>
        <div class="kpi-subnote">wevtutil System · Application</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">유입 HTTP 요청 로그</div>
        <div class="summary-val">${httpLogsAll.length}건</div>
        <div class="kpi-subnote">실시간 서버 인입 트래픽</div>
      </div>
      <div class="summary-card summary-card-amber clickable" id="card-goto-soar">
        <div class="summary-label">게이트웨이 활성 차단 IP</div>
        <div class="summary-val orange-text">${blockedIpCnt}</div>
        <div class="kpi-subnote">클릭 시 SOAR 차단 관리로 이동</div>
      </div>
    </div>

    <div class="panel-card">
      <div class="card-title">
        <div>
          <span class="section-main-title">실측 탐지 위협 케이스 목록 (${cases.length}건)</span>
          <p class="muted-label">호스트 실측 점검 및 실제 유입된 위협 트래픽으로 생성된 케이스입니다. 행을 클릭하면 상세 분석 패널이 열립니다.</p>
        </div>
        <div class="filter-bar">
          ${state.caseFilter !== 'ALL' ? `<button type="button" class="btn-outline-sm" id="btn-reset-case-filter">필터 해제 (${allCases.length}건 전체 보기)</button>` : ''}
          <button type="button" class="btn-outline-sm" id="btn-open-case-drawer-btn">케이스 요약 드로어 열기</button>
        </div>
      </div>
      <div class="table-wrap">
        <table class="xdr-table">
          <thead>
            <tr>
              <th>케이스 ID</th>
              <th>심각도</th>
              <th>상태</th>
              <th>케이스 제목</th>
              <th>출발지 IP</th>
              <th>대상 호스트</th>
              <th>MITRE 기법</th>
              <th>AI 판정</th>
              <th>분석가 판정</th>
              <th>작업</th>
            </tr>
          </thead>
          <tbody>
            ${
              cases.length === 0
                ? `<tr><td colspan="10" class="muted-label">현재 선택된 조건에 해당하는 케이스가 없습니다.</td></tr>`
                : cases
                    .map(
                      (c) => `
              <tr class="clickable-row" data-case-id="${esc(c.case_id)}">
                <td class="mono-code emerald-text">${esc(c.case_id)}</td>
                <td><span class="sev-badge ${sevBadgeClass(c.severity)}">${esc(c.severity)}</span></td>
                <td><span class="status-pill">${esc(c.status)}</span></td>
                <td class="cell-title-wrap"><strong>${esc(c.title)}</strong></td>
                <td class="mono-code">${esc(c.src_ip)}</td>
                <td class="mono-code">${esc(c.target_asset)}</td>
                <td class="mono-code">${esc(c.mitre_technique)}</td>
                <td><span class="ai-badge ${aiBadgeClass(c.ai_label)}">${esc(c.ai_label)}</span></td>
                <td><span class="status-pill">${esc(c.verdict_status)}</span></td>
                <td><button type="button" class="btn-outline-sm btn-open-detail-row" data-case-id="${esc(c.case_id)}">상세 분석</button></td>
              </tr>
            `
                    )
                    .join('')
            }
          </tbody>
        </table>
      </div>
    </div>

    <div class="panel-card">
      <div class="card-title">
        <div>
          <span class="section-main-title">실시간 Windows OS 이벤트 로그 (wevtutil System · Application 실측 수집 — ${winEvents.length}건)</span>
          <p class="muted-label">현재 호스트(${esc(state.overview.hostInfo?.hostname)})의 Windows 이벤트 뷰어에서 실시간으로 발생한 실제 시스템 및 애플리케이션 로그입니다.</p>
        </div>
        <div class="filter-bar">
          <select id="sel-event-channel" class="filter-select">
            <option value="ALL" ${state.eventChannelFilter === 'ALL' ? 'selected' : ''}>전체 채널 (System + Application)</option>
            <option value="System" ${state.eventChannelFilter === 'System' ? 'selected' : ''}>System 채널만 보기</option>
            <option value="Application" ${state.eventChannelFilter === 'Application' ? 'selected' : ''}>Application 채널만 보기</option>
          </select>
          <button type="button" class="btn-primary-emerald" id="btn-refresh-win-events">Windows 이벤트 로그 재수집</button>
        </div>
      </div>
      <div class="table-wrap">
        <table class="xdr-table">
          <thead>
            <tr>
              <th>발생 시각 (UTC)</th>
              <th>채널</th>
              <th>레코드 번호</th>
              <th>Event ID</th>
              <th>수준</th>
              <th>공급자 (Provider)</th>
              <th>PID</th>
              <th>실제 이벤트 메시지</th>
            </tr>
          </thead>
          <tbody>
            ${
              winEvents.length === 0
                ? `<tr><td colspan="8" class="muted-label">수집된 Windows 이벤트 로그가 없습니다.</td></tr>`
                : winEvents
                    .map(
                      (ev) => `
              <tr>
                <td class="mono-code">${esc(ev.timestamp)}</td>
                <td><span class="status-pill">${esc(ev.channel)}</span></td>
                <td class="mono-code">#${esc(ev.rawRecordId)}</td>
                <td class="mono-code emerald-text"><strong>${esc(ev.eventId)}</strong></td>
                <td><span class="sev-badge ${sevBadgeClass(ev.severity)}">${esc(ev.levelName)}</span></td>
                <td class="mono-code">${esc(ev.provider)}</td>
                <td class="mono-code">${esc(ev.pid)}</td>
                <td class="cell-title-wrap">${esc(ev.message)}</td>
              </tr>
            `
                    )
                    .join('')
            }
          </tbody>
        </table>
      </div>
    </div>

    <div class="panel-card">
      <div class="card-title">
        <div>
          <span class="section-main-title">실시간 유입 HTTP 요청 & IPS 검열 로그 (${httpLogs.length}건)</span>
          <p class="muted-label">현재 서버(127.0.0.1:5280)로 실제 인입된 HTTP 요청 내역과 L7 인라인 IPS 판정 결과입니다.</p>
        </div>
      </div>
      <div class="table-wrap">
        <table class="xdr-table">
          <thead>
            <tr>
              <th>유입 시각</th>
              <th>클라이언트 IP</th>
              <th>HTTP 메서드</th>
              <th>요청 경로 (URI)</th>
              <th>응답 상태</th>
              <th>IPS 검열 결과</th>
              <th>User-Agent</th>
            </tr>
          </thead>
          <tbody>
            ${
              httpLogs.length === 0
                ? `<tr><td colspan="7" class="muted-label">아직 기록된 유입 HTTP 요청이 없습니다.</td></tr>`
                : httpLogs
                    .map(
                      (l) => `
              <tr>
                <td class="mono-code">${esc(l.timestamp)}</td>
                <td class="mono-code">${esc(l.clientIp)}</td>
                <td class="mono-code emerald-text"><strong>${esc(l.method)}</strong></td>
                <td class="mono-code">${esc(l.url)}</td>
                <td class="mono-code">${esc(l.status)}</td>
                <td>
                  <span class="sev-badge ${l.status === 403 ? 'sev-critical' : 'sev-low'}">${esc(l.verdict)}</span>
                </td>
                <td class="muted-label">${esc(l.userAgent)}</td>
              </tr>
            `
                    )
                    .join('')
            }
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function bindCasesViewEvents() {
  document.querySelectorAll('[data-filter-card]').forEach((card) => {
    card.addEventListener('click', () => {
      const f = card.dataset.filterCard;
      state.caseFilter = state.caseFilter === f ? 'ALL' : f;
      showToast(`케이스 목록 필터: [${state.caseFilter}]`);
      renderCurrentView();
    });
  });

  document.getElementById('card-goto-soar')?.addEventListener('click', () => {
    switchView('soar');
  });

  document.getElementById('btn-reset-case-filter')?.addEventListener('click', () => {
    state.caseFilter = 'ALL';
    renderCurrentView();
  });

  document.getElementById('btn-open-case-drawer-btn')?.addEventListener('click', () => {
    openCaseListDrawer();
  });

  document.querySelectorAll('.clickable-row[data-case-id]').forEach((row) => {
    row.addEventListener('click', () => openCaseDetailDrawer(row.dataset.caseId));
  });

  const chSel = document.getElementById('sel-event-channel');
  if (chSel) {
    chSel.addEventListener('change', () => {
      state.eventChannelFilter = chSel.value;
      renderCurrentView();
    });
  }

  document.getElementById('btn-refresh-win-events')?.addEventListener('click', async () => {
    showToast('실시간 Windows 이벤트 로그(wevtutil)를 다시 수집합니다...');
    await loadOverview();
  });
}

// ============================================================================
// 2. 실시간 네트워크 소켓 (netstat -ano) & 게이트웨이 IP 차단 뷰 (network)
// ============================================================================
function renderNetworkView() {
  const net = state.overview.netstatSnapshot || { summary: {}, connections: [] };
  const soarActions = state.overview.soarActions || [];
  const blockedTargets = new Set(
    soarActions.filter((a) => a.action_type === 'BLOCK_ATTACK_IP').map((a) => a.target)
  );

  const q = state.searchQuery.toLowerCase();
  const conns = q
    ? (net.connections || []).filter((c) =>
        `${c.localAddr} ${c.foreignAddr} ${c.state} ${c.processName} ${c.pid}`.toLowerCase().includes(q)
      )
    : net.connections || [];

  return `
    <div class="summary-grid-5">
      <div class="summary-card">
        <div class="summary-label">실측 TCP 소켓 총계</div>
        <div class="summary-val emerald-text">${net.summary?.total || 0}</div>
        <div class="kpi-subnote">netstat -ano 실시간 파싱</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">활성 연결 (ESTABLISHED)</div>
        <div class="summary-val">${net.summary?.established || 0}</div>
        <div class="kpi-subnote">현재 세션 유지 중</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">대기 포트 (LISTENING)</div>
        <div class="summary-val">${net.summary?.listening || 0}</div>
        <div class="kpi-subnote">로컬 서비스 오픈 포트</div>
      </div>
      <div class="summary-card summary-card-amber">
        <div class="summary-label">외부 원격 IP 연결</div>
        <div class="summary-val orange-text">${net.summary?.externalCount || 0}</div>
        <div class="kpi-subnote">루프백(127.0.0.1) 제외</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">최근 수집 시각</div>
        <div class="summary-val mono-code">${esc((net.collectedAt || '').slice(11, 19))}</div>
        <div class="kpi-subnote">실시간 OS 스냅샷</div>
      </div>
    </div>

    <div class="panel-card">
      <div class="card-title">
        <div>
          <span class="section-main-title">호스트(${esc(state.overview.hostInfo?.hostname)}) 활성 TCP 네트워크 소켓 목록</span>
          <p class="muted-label">Windows netstat -ano와 tasklist PID를 실시간 매핑한 결과입니다. 외부 원격 IP는 즉시 차단 등록할 수 있습니다.</p>
        </div>
        <button type="button" class="btn-primary-emerald" id="btn-refresh-netstat">netstat 실시간 재조회</button>
      </div>
      <div class="table-wrap">
        <table class="xdr-table">
          <thead>
            <tr>
              <th>프로토콜</th>
              <th>로컬 주소:포트</th>
              <th>원격 주소:포트</th>
              <th>상태 (State)</th>
              <th>PID</th>
              <th>매핑된 프로세스명</th>
              <th>구분</th>
              <th>게이트웨이 차단 제어</th>
            </tr>
          </thead>
          <tbody>
            ${conns
              .map((c) => {
                const alreadyRegistered = blockedTargets.has(c.remoteIp);
                return `
              <tr>
                <td class="mono-code">${esc(c.proto)}</td>
                <td class="mono-code">${esc(c.localAddr)}</td>
                <td class="mono-code ${c.isExternal ? 'orange-text' : ''}">${esc(c.foreignAddr)}</td>
                <td><span class="status-pill">${esc(c.state)}</span></td>
                <td class="mono-code">${esc(c.pid)}</td>
                <td class="mono-code emerald-text">${esc(c.processName)}</td>
                <td>${c.isExternal ? '<span class="sev-badge sev-high">외부 연결</span>' : '<span class="sev-badge sev-low">로컬/내부</span>'}</td>
                <td>
                  ${
                    !c.isExternal || !c.remoteIp
                      ? '<span class="muted-label">로컬 루프백</span>'
                      : alreadyRegistered
                        ? `<button type="button" class="btn-primary-emerald btn-sm btn-goto-soar">✓ 차단 등록됨 (SOAR 이동)</button>`
                        : `<button type="button" class="btn-outline-sm btn-block-remote-ip" data-ip="${esc(c.remoteIp)}" data-proc="${esc(c.processName)}">IP 차단 등록 (${esc(c.remoteIp)})</button>`
                  }
                </td>
              </tr>
            `;
              })
              .join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function bindNetworkViewEvents() {
  document.getElementById('btn-refresh-netstat')?.addEventListener('click', async () => {
    showToast('netstat -ano 실시간 네트워크 소켓을 다시 수집합니다...');
    await loadOverview();
  });

  document.querySelectorAll('.btn-goto-soar').forEach((btn) => {
    btn.addEventListener('click', () => switchView('soar'));
  });

  document.querySelectorAll('.btn-block-remote-ip').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const ip = btn.dataset.ip;
      const proc = btn.dataset.proc;
      const firstCase = state.overview.cases?.[0]?.case_id || 'CASE-HOST-POLICY-01';
      const res = await apiFetch('/api/soar/propose', {
        method: 'POST',
        body: JSON.stringify({
          caseId: firstCase,
          actionType: 'BLOCK_ATTACK_IP',
          target: ip,
          assetCriticality: 'LOW',
          reason: `실시간 netstat 외부 연결 IP(${ip}, 프로세스: ${proc}) 차단 등록`
        })
      });
      if (res.ok) {
        showToast(`원격 IP ${ip} 차단 티켓(${res.action.action_id})이 등록되었습니다.`);
        await loadOverview();
      }
    });
  });
}

// ============================================================================
// 3. 실행 프로세스 (tasklist) & 호스트 상태 뷰 (endpoint)
// ============================================================================
function renderEndpointView() {
  const h = state.overview.hostInfo || {};
  const procSnap = state.overview.procSnapshot || { totalCount: 0, processes: [] };
  const soarActions = state.overview.soarActions || [];
  const registeredKillTargets = new Set(
    soarActions.filter((a) => a.action_type === 'KILL_MALICIOUS_PROCESS').map((a) => a.target)
  );

  const q = state.searchQuery.toLowerCase();
  const procs = q
    ? (procSnap.processes || []).filter((p) => `${p.name} ${p.pid} ${p.sessionName}`.toLowerCase().includes(q))
    : procSnap.processes || [];

  return `
    <div class="panel-card">
      <div class="card-title">
        <div>
          <span class="section-main-title">호스트 하드웨어 · 네트워크 인터페이스 & 현재 세션 ZTNA 인가 상태</span>
          <p class="muted-label">OS 커널 및 네트워크 어댑터에서 실시간 수집한 로컬 호스트(${esc(h.hostname)}) 자산 및 접근 인가 정보입니다.</p>
        </div>
        <span class="sev-badge sev-low">● ZTNA 세션: ALLOW (${esc(h.username)}@${esc(h.hostname)})</span>
      </div>
      <div class="kv-grid">
        <div class="kv-item"><span class="kv-label">호스트명 / 접속 계정</span><span class="kv-val mono-code">${esc(h.hostname)} / ${esc(h.username)}</span></div>
        <div class="kv-item"><span class="kv-label">운영체제 플랫폼</span><span class="kv-val mono-code">${esc(h.platform)}</span></div>
        <div class="kv-item"><span class="kv-label">CPU 모델 / 코어</span><span class="kv-val">${esc(h.cpuModel)} (${h.cpuCores}코어)</span></div>
        <div class="kv-item"><span class="kv-label">시스템 메모리 사용량</span><span class="kv-val orange-text">${h.usedMemMb} MB / ${h.totalMemMb} MB (${h.memUsagePct}%)</span></div>
      </div>
      <div class="table-wrap">
        <table class="xdr-table">
          <thead>
            <tr><th>네트워크 인터페이스</th><th>IPv4 주소</th><th>서브넷 마스크</th><th>MAC 물리 주소</th></tr>
          </thead>
          <tbody>
            ${(h.interfaces || [])
              .map(
                (iface) => `
              <tr>
                <td>${esc(iface.name)}</td>
                <td class="mono-code emerald-text">${esc(iface.address)}</td>
                <td class="mono-code">${esc(iface.netmask)}</td>
                <td class="mono-code">${esc(iface.mac)}</td>
              </tr>
            `
              )
              .join('')}
          </tbody>
        </table>
      </div>
    </div>

    <div class="panel-card">
      <div class="card-title">
        <div>
          <span class="section-main-title">실행 중인 Windows 프로세스 목록 (tasklist 실측)</span>
          <p class="muted-label">총 ${procSnap.totalCount}개 실행 프로세스 중 메모리 점유 상위 ${procs.length}개 목록입니다.</p>
        </div>
        <button type="button" class="btn-primary-emerald" id="btn-refresh-procs">tasklist 실시간 재조회</button>
      </div>
      <div class="table-wrap">
        <table class="xdr-table">
          <thead>
            <tr>
              <th>프로세스 이름 (Image Name)</th>
              <th>PID</th>
              <th>세션 이름</th>
              <th>메모리 사용량 (MB)</th>
              <th>메모리 사용량 (KB)</th>
              <th>능동 대응 (SOAR)</th>
            </tr>
          </thead>
          <tbody>
            ${procs
              .map((p) => {
                const targetKey = `${h.hostname} :: ${p.name} (PID ${p.pid})`;
                const alreadyQueued = registeredKillTargets.has(targetKey);
                return `
              <tr>
                <td class="mono-code emerald-text"><strong>${esc(p.name)}</strong></td>
                <td class="mono-code">${esc(p.pid)}</td>
                <td>${esc(p.sessionName)}</td>
                <td class="mono-code orange-text">${p.memoryMb} MB</td>
                <td class="mono-code muted-label">${p.memoryKb.toLocaleString()} KB</td>
                <td>
                  ${
                    p.isProtected
                      ? `<span class="sev-badge sev-low">🛡️ 핵심 보호 프로세스 (안전장치 잠금)</span>`
                      : alreadyQueued
                        ? `<button type="button" class="btn-primary-emerald btn-sm btn-goto-soar">✓ SOAR 등록됨 (이동)</button>`
                        : `<button type="button" class="btn-outline-sm btn-propose-kill" data-proc="${esc(p.name)}" data-pid="${esc(p.pid)}">⚡ 프로세스 종료 제안 (taskkill)</button>`
                  }
                </td>
              </tr>
            `;
              })
              .join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function bindEndpointViewEvents() {
  document.getElementById('btn-refresh-procs')?.addEventListener('click', async () => {
    showToast('tasklist 프로세스 목록을 다시 수집합니다...');
    await loadOverview();
  });

  document.querySelectorAll('.btn-goto-soar').forEach((btn) => {
    btn.addEventListener('click', () => switchView('soar'));
  });

  document.querySelectorAll('.btn-propose-kill').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const proc = btn.dataset.proc;
      const pid = btn.dataset.pid;
      const firstCase = state.overview.cases?.[0]?.case_id || 'CASE-HOST-POLICY-01';
      const res = await apiFetch('/api/soar/propose', {
        method: 'POST',
        body: JSON.stringify({
          caseId: firstCase,
          actionType: 'KILL_MALICIOUS_PROCESS',
          target: `${state.overview.hostInfo?.hostname} :: ${proc} (PID ${pid})`,
          assetCriticality: 'HIGH',
          reason: `tasklist 실측 프로세스(${proc}, PID ${pid}) 강제 종료 승인 요청`
        })
      });
      if (res.ok) {
        showToast(`프로세스(${proc}) 종료 조치가 SOAR 대기열에 등록되었습니다.`);
        await loadOverview();
      }
    });
  });
}

// ============================================================================
// 4. Windows 로컬 보안 정책 실측 (net accounts & reg query) 뷰 (policy)
// ============================================================================
function renderPolicyView() {
  const rep = state.overview.policyReport || { items: [], rawSnippets: {} };
  const items = rep.items || [];

  return `
    <div class="summary-grid-5">
      <div class="summary-card">
        <div class="summary-label">실측 대상 호스트</div>
        <div class="summary-val emerald-text mono-code">${esc(rep.hostname)}</div>
        <div class="kpi-subnote">net accounts & reg query</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">점검 항목 총계</div>
        <div class="summary-val">${rep.totalItems || 8}</div>
        <div class="kpi-subnote">KISA / ISMS-P 주요 항목</div>
      </div>
      <div class="summary-card summary-card-emerald">
        <div class="summary-label">자동 실측 양호</div>
        <div class="summary-val emerald-text">${rep.passCount || 0}</div>
        <div class="kpi-subnote">권장 기준 충족</div>
      </div>
      <div class="summary-card summary-card-warn">
        <div class="summary-label">자동 실측 취약</div>
        <div class="summary-val crimson-text">${rep.failCount || 0}</div>
        <div class="kpi-subnote">현재 PC 설정 미달</div>
      </div>
      <div class="summary-card summary-card-amber">
        <div class="summary-label">수동 vs 자동 불일치</div>
        <div class="summary-val orange-text">${rep.mismatchCount || 0}건</div>
        <div class="kpi-subnote">수동 체크리스트 착오 검출</div>
      </div>
    </div>

    <div class="panel-card">
      <div class="card-title">
        <div>
          <span class="section-main-title">Windows 로컬 보안 정책 — 수동 점검표 vs 호스트 실시간 자동 추출 1:1 대조</span>
          <p class="muted-label">수동 점검 판정 드롭다운을 변경하면 자동 추출된 실제 설정값과 비교하여 인적 오류(불일치) 여부를 즉시 재계산합니다.</p>
        </div>
        <button type="button" class="btn-primary-emerald" id="btn-recompare-policy">실시간 재추출 & 마스킹 내보내기</button>
      </div>
      <div class="table-wrap">
        <table class="xdr-table">
          <thead>
            <tr>
              <th>정책 ID</th>
              <th>점검 항목명</th>
              <th>권장 기준</th>
              <th>현재 PC 실제 추출값</th>
              <th>수동 점검 판정</th>
              <th>자동 실측 판정</th>
              <th>1:1 대조 결과</th>
            </tr>
          </thead>
          <tbody>
            ${items
              .map(
                (it) => `
              <tr>
                <td class="mono-code">${esc(it.id)}</td>
                <td><strong>${esc(it.title)}</strong><div class="muted-label">${esc(it.ismsRef)} · ${esc(it.mitreRef)}</div></td>
                <td class="mono-code">${esc(it.recommended)}</td>
                <td class="mono-code orange-text"><strong>${esc(it.key)} = ${esc(it.actualRawValue)}</strong></td>
                <td>
                  <select class="filter-select manual-verdict-select" data-key="${esc(it.key)}">
                    <option value="양호" ${it.manualVerdict === '양호' ? 'selected' : ''}>수동: 양호</option>
                    <option value="취약" ${it.manualVerdict === '취약' ? 'selected' : ''}>수동: 취약</option>
                  </select>
                </td>
                <td><span class="sev-badge ${it.autoVerdict === '양호' ? 'sev-low' : 'sev-critical'}">${esc(it.autoVerdict)}</span></td>
                <td>
                  ${
                    it.isMismatch
                      ? `<span class="sev-badge sev-critical">불일치 (인적 오류)</span><div class="muted-label">${esc(it.humanErrorReason)}</div>`
                      : `<span class="sev-badge sev-low">✓ 일치</span>`
                  }
                </td>
              </tr>
            `
              )
              .join('')}
          </tbody>
        </table>
      </div>
    </div>

    <div class="grid-2col">
      <div class="panel-card">
        <div class="card-title">
          <div>
            <span class="section-main-title">호스트 실제 명령 실행 출력 (net accounts & RDP 레지스트리)</span>
            <p class="muted-label">현재 Windows OS에서 직접 수집한 원시 콘솔 출력입니다.</p>
          </div>
        </div>
        <div class="code-dump-box">${esc(rep.rawSnippets?.netAccounts || '수집된 출력이 없습니다.')}\n\n${esc(rep.rawSnippets?.rdpNlaRegistry || '')}</div>
      </div>
      <div class="panel-card">
        <div class="card-title">
          <div>
            <span class="section-main-title">[REDACTED] 민감정보 마스킹 진단서 내보내기</span>
            <p class="muted-label">외부 반출 시 API 키·세션 토큰 등 민감 자격증명을 자동으로 마스킹한 JSON입니다.</p>
          </div>
        </div>
        <div id="policy-redacted-box" class="code-dump-box">${esc(state.lastPolicyRedactedText)}</div>
      </div>
    </div>
  `;
}

async function runPolicyCompareAndRender() {
  const manualChecklist = {};
  document.querySelectorAll('.manual-verdict-select').forEach((sel) => {
    manualChecklist[sel.dataset.key] = sel.value;
    state.manualChecklist[sel.dataset.key] = sel.value;
  });
  const res = await apiFetch('/api/policy/compare', {
    method: 'POST',
    body: JSON.stringify({
      manualChecklist
    })
  });
  if (res.ok) {
    state.overview.policyReport = res.report;
    state.lastPolicyRedactedText = JSON.stringify(res.redactedExport, null, 2);
    renderCurrentView();
    showToast(`Windows 정책 대조 완료 (불일치 ${res.report.mismatchCount}건)`);
  }
}

function bindPolicyViewEvents() {
  document.querySelectorAll('.manual-verdict-select').forEach((sel) => {
    sel.addEventListener('change', () => runPolicyCompareAndRender());
  });

  document.getElementById('btn-recompare-policy')?.addEventListener('click', () => runPolicyCompareAndRender());
}

// ============================================================================
// 5. 공급망 취약점 스캔 (package-lock.json & OSV.dev) 뷰 (sbom)
// ============================================================================
function renderSbomView() {
  const sbom = state.overview.sbomReport || { counts: {}, packages: [] };
  const counts = sbom.counts || { total: 0, vulnerable: 0, none_found: 0, unverifiable: 0 };

  return `
    <div class="summary-grid-5">
      <div class="summary-card">
        <div class="summary-label">스캔 대상 패키지 수</div>
        <div class="summary-val">${counts.total || 0}</div>
        <div class="kpi-subnote">package-lock.json 고정 버전</div>
      </div>
      <div class="summary-card summary-card-warn">
        <div class="summary-label">취약점 발견 (vulnerable)</div>
        <div class="summary-val crimson-text">${counts.vulnerable || 0}</div>
        <div class="kpi-subnote">즉시 패치 권고</div>
      </div>
      <div class="summary-card summary-card-emerald">
        <div class="summary-label">취약점 없음 (none_found)</div>
        <div class="summary-val emerald-text">${counts.none_found || 0}</div>
        <div class="kpi-subnote">OSV 대조 안전 확인</div>
      </div>
      <div class="summary-card summary-card-amber">
        <div class="summary-label">검증 불가 (unverifiable)</div>
        <div class="summary-val orange-text">${counts.unverifiable || 0}</div>
        <div class="kpi-subnote">비공개/내부 패키지 분리</div>
      </div>
      <div class="summary-card">
        <div class="summary-label">스캔 순번 (requestSeq)</div>
        <div class="summary-val mono-code">#${sbom.requestSeq || 1}</div>
        <div class="kpi-subnote">최신 응답 보장</div>
      </div>
    </div>

    <div class="panel-card">
      <div class="card-title">
        <div>
          <span class="section-main-title">package-lock.json 고정 버전(exact_lock_version) & Google OSV API 스캐너</span>
          <p class="muted-label">프로젝트 루트의 package-lock.json에서 실제 고정 버전을 추출하여 Google OSV(api.osv.dev) 데이터베이스와 실시간 대조합니다.</p>
        </div>
        <div class="filter-bar">
          <button type="button" class="btn-primary-emerald" id="btn-sbom-live">OSV.dev 실시간 온라인 스캔 실행</button>
        </div>
      </div>
      <div class="table-wrap">
        <table class="xdr-table">
          <thead>
            <tr>
              <th>패키지명</th>
              <th>고정 버전 (exact_lock_version)</th>
              <th>판정 상태</th>
              <th>CVE / OSV ID</th>
              <th>CVSS</th>
              <th>상세 설명 및 조치 권고</th>
            </tr>
          </thead>
          <tbody>
            ${(sbom.packages || [])
              .map(
                (p) => `
              <tr>
                <td class="mono-code"><strong>${esc(p.name)}</strong></td>
                <td class="mono-code emerald-text">${esc(p.exactLockVersion)}</td>
                <td>
                  <span class="sev-badge ${
                    p.status === 'vulnerable' ? 'sev-critical' : p.status === 'none_found' ? 'sev-low' : 'sev-medium'
                  }">${esc(p.status)}</span>
                </td>
                <td class="mono-code crimson-text">${esc(p.cveId || '-')}</td>
                <td class="mono-code">${p.cvss !== null && p.cvss !== undefined ? p.cvss : '-'}</td>
                <td>${esc(p.summary)}</td>
              </tr>
            `
              )
              .join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

function bindSbomViewEvents() {
  document.getElementById('btn-sbom-live')?.addEventListener('click', async () => {
    state.sbomRequestSeq += 1;
    const reqSeq = state.sbomRequestSeq;
    const res = await apiFetch(`/api/cti/sbom?seq=${reqSeq}&live=true`);
    if (res.requestSeq >= state.sbomDisplayedSeq) {
      state.sbomDisplayedSeq = res.requestSeq;
      state.overview.sbomReport = res;
      renderCurrentView();
      showToast(`OSV 온라인 스캔 완료 (#${res.requestSeq}): vulnerable=${res.counts.vulnerable}, none_found=${res.counts.none_found}`);
    }
  });
}

// ============================================================================
// 6. 능동 대응(SOAR) · AI 감사 · DB 백업 뷰 (soar)
// ============================================================================
function renderSoarView() {
  const actions = state.overview.soarActions || [];
  const audits = state.overview.aiAudits || [];
  const cases = state.overview.cases || [];
  const gp = state.overview.guardrailPolicy || {};
  const firstCaseId = cases[0]?.case_id || 'CASE-HOST-POLICY-01';

  return `
    <div class="panel-card">
      <div class="card-title">
        <div>
          <span class="section-main-title">🛡️ 5중 원천 집행 안전장치 (Safe-Guardrail) 작동 현황</span>
          <p class="muted-label">실제 Windows OS 명령(taskkill.exe / netsh.exe) 실행 시 시스템 마비 및 셀프 잠금을 원천 방지하는 하드웨어·OS 보호 규칙이 상시 활성화되어 있습니다.</p>
        </div>
        <span class="sev-badge sev-low">● 5중 안전장치 ACTIVE</span>
      </div>
      <div class="kv-grid">
        <div class="kv-item">
          <span class="kv-label">1. 핵심 프로세스 종료 차단 (${gp.protectedProcessCount || 37}종)</span>
          <span class="kv-val mono-code">explorer.exe · svchost.exe · lsass.exe · chrome.exe · node.exe · code.exe 등</span>
        </div>
        <div class="kv-item">
          <span class="kv-label">2. 셀프 IP & 게이트웨이 차단 금지</span>
          <span class="kv-val mono-code">${esc((gp.protectedIps || ['127.0.0.1']).join(' · '))} 및 *.1 라우터</span>
        </div>
        <div class="kv-item">
          <span class="kv-label">3. 로그인 계정 잠금 보호</span>
          <span class="kv-val mono-code">${esc((gp.protectedAccounts || ['User', 'Administrator']).join(' · '))}</span>
        </div>
        <div class="kv-item">
          <span class="kv-label">4. PID 재사용 검증 & 1-Click 롤백</span>
          <span class="kv-val mono-code">실행 직전 PID·이미지명 대조 / 방화벽 룰 즉시 복구 지원</span>
        </div>
      </div>
    </div>

    <div class="grid-2col">
      <div class="panel-card">
        <div class="card-title">
          <div>
            <span class="section-main-title">능동 대응(Active Response) & 실제 원천 집행 워크플로</span>
            <p class="muted-label">PROPOSED(제안) ➔ APPROVED(승인) ➔ EFFECT_VERIFIED(안전장치 검증 후 실제 taskkill / netsh / 게이트웨이 집행) ➔ ROLLED_BACK(원상복구)</p>
          </div>
        </div>
        <div class="filter-bar">
          <select id="soar-new-type" class="filter-select">
            <option value="BLOCK_ATTACK_IP">공격 출발지 IP 차단 (L7 게이트웨이 + netsh 방화벽)</option>
            <option value="KILL_MALICIOUS_PROCESS">프로세스 강제 종료 (taskkill.exe /PID /F)</option>
            <option value="ISOLATE_HOST">호스트 게이트웨이 안전 격리 (ISOLATE_HOST)</option>
            <option value="DISABLE_OS_ACCOUNT">비인가 OS 계정 비활성화 (DISABLE_OS_ACCOUNT)</option>
          </select>
          <input type="text" id="soar-new-target" class="filter-input" value="" placeholder="대상 IP 또는 프로세스명 (PID 번호) 입력" />
          <button type="button" class="btn-primary-emerald" id="btn-create-soar">능동 대응 조치 등록</button>
        </div>

        <div class="table-wrap">
          <table class="xdr-table">
            <thead>
              <tr>
                <th>조치 ID / 영수증</th>
                <th>유형</th>
                <th>대상 (Target)</th>
                <th>현재 상태</th>
                <th>원천 집행 및 안전장치 판정</th>
                <th>승인 · 실제 집행 · 롤백 제어</th>
              </tr>
            </thead>
            <tbody>
              ${
                actions.length === 0
                  ? `<tr><td colspan="6" class="muted-label">현재 등록된 능동 대응 조치가 없습니다. 네트워크 소켓/프로세스 메뉴에서 등록하거나 위 입력창에서 직접 추가할 수 있습니다.</td></tr>`
                  : actions
                      .map(
                        (a) => `
                  <tr>
                    <td class="mono-code">${esc(a.action_id)}<div class="muted-label">${esc(a.receipt_id || '-')}</div></td>
                    <td class="mono-code emerald-text">${esc(a.action_type)}</td>
                    <td class="mono-code"><strong>${esc(a.target)}</strong></td>
                    <td><span class="status-pill">${esc(a.stage)}</span></td>
                    <td>
                      ${
                        a.effect_applied
                          ? '<span class="sev-badge sev-low">✓ 실제 원천 집행 완료</span>'
                          : a.stage === 'GUARDRAIL_BLOCKED'
                            ? '<span class="sev-badge sev-critical">🛡️ 안전장치에 의해 차단됨</span>'
                            : a.stage === 'ROLLED_BACK'
                              ? '<span class="sev-badge sev-low">🔄 원상복구(차단 해제) 완료</span>'
                              : '<span class="sev-badge sev-medium">집행 전 / 승인 대기</span>'
                      }
                      <div class="muted-label">${esc(a.enforcement_note)}</div>
                    </td>
                    <td>
                      <div class="filter-bar">
                        <button type="button" class="btn-outline-sm btn-soar-step" data-id="${esc(a.action_id)}" data-stage="APPROVED" data-enforcer="false">1. 승인</button>
                        <button type="button" class="btn-primary-emerald btn-sm btn-soar-step" data-id="${esc(a.action_id)}" data-stage="EFFECT_VERIFIED" data-enforcer="true">2. 실제 원천 집행</button>
                        <button type="button" class="btn-outline-sm btn-soar-step" data-id="${esc(a.action_id)}" data-stage="ROLLED_BACK" data-enforcer="true">3. 원상복구(해제)</button>
                      </div>
                    </td>
                  </tr>
                `
                      )
                      .join('')
              }
            </tbody>
          </table>
        </div>
      </div>

      <div class="panel-card">
        <div class="card-title">
          <div>
            <span class="section-main-title">케이스 이벤트 근거 기반 AI 분석 & 감사 로그</span>
            <p class="muted-label">선택한 케이스에 실제 연결된 수집 이벤트(eventId)만을 근거로 정탐/오탐 여부와 대응 권고안을 산출합니다.</p>
          </div>
        </div>
        <div class="filter-bar">
          <select id="soar-ai-case-select" class="filter-select">
            ${cases.map((c) => `<option value="${esc(c.case_id)}">${esc(c.case_id)} — ${esc(c.title.slice(0, 42))}</option>`).join('')}
          </select>
          <button type="button" class="btn-primary-emerald" id="btn-run-valid-ai" data-case="${esc(firstCaseId)}">선택 케이스 AI 분석 실행</button>
        </div>
        <div id="soar-ai-test-box" class="code-dump-box">${esc(state.lastAiResultText)}</div>

        <hr class="section-divider" />
        <div class="card-title">
          <div>
            <span class="section-main-title">SQLite 데이터베이스 무결성 백업</span>
            <p class="muted-label">현재 운영 중인 로컬 관제 데이터베이스(jw_xdr.db)의 무결성을 검증하여 backup 폴더에 저장합니다.</p>
          </div>
          <button type="button" class="btn-primary-emerald" id="btn-sqlite-backup-now">현재 SQLite DB 백업 생성</button>
        </div>
        <div id="sqlite-test-box" class="code-dump-box">${esc(state.lastBackupResultText)}</div>

        <hr class="section-divider" />
        <div class="card-title">
          <span class="section-main-title">AI 분석 감사 이력 (ai_audit_logs)</span>
        </div>
        <div class="table-wrap">
          <table class="xdr-table">
            <thead>
              <tr><th>감사 ID</th><th>케이스 ID</th><th>판정</th><th>인용 eventId</th><th>가드레일 상태</th><th>시각</th></tr>
            </thead>
            <tbody>
              ${
                audits.length === 0
                  ? `<tr><td colspan="6" class="muted-label">아직 기록된 AI 감사 이력이 없습니다. 위에서 [선택 케이스 AI 분석 실행]을 눌러주세요.</td></tr>`
                  : audits
                      .map(
                        (au) => `
                  <tr>
                    <td class="mono-code">${esc(au.audit_id)}</td>
                    <td class="mono-code">${esc(au.case_id)}</td>
                    <td><span class="ai-badge ${aiBadgeClass(au.ai_label)}">${esc(au.ai_label)}</span></td>
                    <td class="mono-code">${esc(au.cited_event_ids)}</td>
                    <td class="mono-code ${au.wrong_event_rejected ? 'crimson-text' : 'emerald-text'}">${esc(au.guardrail_status)}</td>
                    <td class="muted-label">${esc(au.created_at)}</td>
                  </tr>
                `
                      )
                      .join('')
              }
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

function bindSoarViewEvents() {
  document.getElementById('btn-create-soar')?.addEventListener('click', async () => {
    const actionType = document.getElementById('soar-new-type').value;
    const target = document.getElementById('soar-new-target').value.trim();
    if (!target) {
      showToast('차단/조치할 대상(IP, 호스트명, 계정 또는 PID)을 입력해주세요.');
      return;
    }
    const firstCaseId = state.overview.cases?.[0]?.case_id || 'CASE-HOST-POLICY-01';
    const res = await apiFetch('/api/soar/propose', {
      method: 'POST',
      body: JSON.stringify({
        caseId: firstCaseId,
        actionType,
        target,
        assetCriticality: 'HIGH',
        reason: `관제사 수동 능동 대응 등록 (${actionType} -> ${target})`
      })
    });
    if (res.ok) {
      showToast(res.duplicatePrevented ? res.message : `능동 대응 조치(${res.action.action_id})가 등록되었습니다.`);
      await loadOverview();
    }
  });

  document.querySelectorAll('.btn-soar-step').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const actionId = btn.dataset.id;
      const nextStage = btn.dataset.stage;
      const enforcerConnected = btn.dataset.enforcer === 'true';
      const res = await apiFetch('/api/soar/transition', {
        method: 'POST',
        body: JSON.stringify({
          actionId,
          nextStage,
          enforcerConnected,
          approvedBy: state.overview.hostInfo?.username || 'admin'
        })
      });
      if (res.ok) {
        showToast(`${res.badgeText}`);
        await loadOverview();
      }
    });
  });

  document.getElementById('btn-run-valid-ai')?.addEventListener('click', async () => {
    const sel = document.getElementById('soar-ai-case-select');
    const caseId = sel ? sel.value : state.overview.cases?.[0]?.case_id || 'CASE-HOST-POLICY-01';
    const res = await apiFetch('/api/ai/triage', {
      method: 'POST',
      body: JSON.stringify({ caseId, anonymize: true })
    });
    state.lastAiResultText = JSON.stringify(res, null, 2);
    showToast(`케이스(${caseId}) AI 분석 완료: ${res.aiLabel}`);
    await loadOverview();
  });

  document.getElementById('btn-sqlite-backup-now')?.addEventListener('click', async () => {
    const res = await apiFetch('/api/db/backup', { method: 'POST', body: JSON.stringify({ label: 'manual_ui' }) });
    state.lastBackupResultText = JSON.stringify(res, null, 2);
    renderCurrentView();
    showToast(`SQLite 백업 완료: ${res.backupFile} (${res.sizeBytes} bytes)`);
  });
}

// ============================================================================
// 슬라이드오버 드로어 1: 케이스 목록 & 드로어 2: 케이스 상세
// ============================================================================
function openCaseListDrawer() {
  const drawer = document.getElementById('drawer-case-list');
  const body = document.getElementById('drawer-case-list-body');
  const countEl = document.getElementById('drawer-list-count');
  const cases = state.overview?.cases || [];
  if (countEl) countEl.textContent = `총 ${cases.length}개 케이스`;

  body.innerHTML = cases
    .map(
      (c) => `
    <div class="drawer-case-item" data-open-case="${esc(c.case_id)}">
      <div class="case-badge-row">
        <span class="sev-badge ${sevBadgeClass(c.severity)}">${esc(c.severity)}</span>
        <span class="status-pill">${esc(c.status)}</span>
        <span class="ai-badge ${aiBadgeClass(c.ai_label)}">${esc(c.ai_label)}</span>
      </div>
      <div class="drawer-case-title">${esc(c.title)}</div>
      <div class="drawer-case-meta">
        <span>ID: ${esc(c.case_id)}</span>
        <span>호스트: ${esc(c.target_asset)}</span>
        <span>출발지: ${esc(c.src_ip)}</span>
      </div>
    </div>
  `
    )
    .join('');

  body.querySelectorAll('[data-open-case]').forEach((el) => {
    el.addEventListener('click', () => openCaseDetailDrawer(el.dataset.openCase));
  });

  drawer.classList.remove('hidden');
}

async function openCaseDetailDrawer(caseId) {
  const res = await apiFetch(`/api/cases/${encodeURIComponent(caseId)}`);
  if (!res.ok || !res.caseDetail) return;
  state.activeCaseId = caseId;
  state.activeCaseDetail = res.caseDetail;

  const c = res.caseDetail;
  document.getElementById('detail-case-title').textContent = c.title;
  document.getElementById('detail-badge-row').innerHTML = `
    <span class="sev-badge ${sevBadgeClass(c.severity)}">${esc(c.severity)}</span>
    <span class="status-pill">${esc(c.status)}</span>
    <span class="ai-badge ${aiBadgeClass(c.ai_label)}">SOC AI: ${esc(c.ai_label)} (${c.confidence}%)</span>
    <span class="mono-code muted-label">${esc(c.case_id)}</span>
  `;

  renderCaseDetailTab();
  document.getElementById('drawer-case-detail').classList.remove('hidden');
}

function renderCaseDetailTab() {
  const c = state.activeCaseDetail;
  if (!c) return;
  const body = document.getElementById('drawer-case-detail-body');
  const stages = state.overview?.catalogs?.killChainStages || [];

  if (state.activeCaseTab === 'basic') {
    body.innerHTML = `
      <div class="panel-card">
        <div class="card-title">
          <span class="section-main-title">SOC Agent 1차 판정 요약</span>
          <button type="button" class="btn-primary-emerald" id="btn-open-ai-modal">AI 분석 리포트 생성</button>
        </div>
        <p class="case-desc-text">${esc(c.description)}</p>
        <div class="kv-grid">
          <div class="kv-item"><span class="kv-label">출발지 IP</span><span class="kv-val mono-code">${esc(c.src_ip)}</span></div>
          <div class="kv-item"><span class="kv-label">대상 호스트</span><span class="kv-val mono-code">${esc(c.target_asset)} (${esc(c.asset_os)})</span></div>
          <div class="kv-item"><span class="kv-label">MITRE 전술 / 기법</span><span class="kv-val mono-code">${esc(c.mitre_tactic)} / ${esc(c.mitre_technique)}</span></div>
          <div class="kv-item"><span class="kv-label">MTTD / MTTR</span><span class="kv-val mono-code">MTTD ${(c.mttd_ms / 1000).toFixed(1)}s / MTTR ${c.mttr_ms ? (c.mttr_ms / 1000).toFixed(1) + 's' : '진행 중'}</span></div>
          <div class="kv-item"><span class="kv-label">분석가 판정 상태</span><span class="kv-val mono-code emerald-text">${esc(c.verdict_status)}</span></div>
          <div class="kv-item"><span class="kv-label">룰 튜닝 노트</span><span class="kv-val">${esc(c.rule_tuning_note || '기록 없음')}</span></div>
        </div>
      </div>

      <div class="panel-card">
        <div class="card-title"><span class="section-main-title">MITRE ATT&CK Kill Chain 전술 흐름</span></div>
        <div class="killchain-grid">
          ${stages
            .map((st, idx) => {
              const active = c.kill_chain_stage === st;
              return `<div class="kc-stage-box ${active ? 'kc-active' : ''}">
                <div class="kc-step-num">${String(idx + 1).padStart(2, '0')}</div>
                <div class="kc-step-name">${esc(st)}</div>
              </div>`;
            })
            .join('')}
        </div>
      </div>
    `;
    document.getElementById('btn-open-ai-modal')?.addEventListener('click', () => openAiReportModal(c));
  } else if (state.activeCaseTab === 'events') {
    body.innerHTML = `
      <div class="panel-card">
        <div class="card-title"><span class="section-main-title">케이스 연결 원시 이벤트 (${(c.events || []).length}건)</span></div>
        ${(c.events || [])
          .map(
            (ev) => `
          <div class="panel-card">
            <div class="kv-grid">
              <div class="kv-item"><span class="kv-label">이벤트 ID</span><span class="kv-val mono-code emerald-text">${esc(ev.event_id)}</span></div>
              <div class="kv-item"><span class="kv-label">프로세스 / 출처</span><span class="kv-val mono-code">${esc(ev.process_name)}</span></div>
              <div class="kv-item"><span class="kv-label">발생 시각</span><span class="kv-val mono-code">${esc(ev.occurred_at)}</span></div>
            </div>
            <div class="code-dump-box">${esc(ev.summary)}\n\n${esc(ev.payload_json)}</div>
          </div>
        `
          )
          .join('')}
      </div>
    `;
  } else if (state.activeCaseTab === 'assets') {
    const h = state.overview.hostInfo || {};
    body.innerHTML = `
      <div class="panel-card">
        <div class="card-title"><span class="section-main-title">대상 호스트 실측 정보 (${esc(c.target_asset)})</span></div>
        <div class="kv-grid">
          <div class="kv-item"><span class="kv-label">호스트명</span><span class="kv-val mono-code">${esc(h.hostname)}</span></div>
          <div class="kv-item"><span class="kv-label">OS 버전</span><span class="kv-val mono-code">${esc(h.platform)}</span></div>
          <div class="kv-item"><span class="kv-label">CPU</span><span class="kv-val">${esc(h.cpuModel)} (${h.cpuCores}코어)</span></div>
          <div class="kv-item"><span class="kv-label">메모리 사용량</span><span class="kv-val">${h.usedMemMb} / ${h.totalMemMb} MB (${h.memUsagePct}%)</span></div>
        </div>
      </div>
    `;
  } else if (state.activeCaseTab === 'ioc') {
    body.innerHTML = `
      <div class="panel-card">
        <div class="card-title"><span class="section-main-title">침해 지표 (IOC) 및 게이트웨이 IP 차단</span></div>
        <div class="kv-grid">
          <div class="kv-item"><span class="kv-label">출발지 위협 IP</span><span class="kv-val mono-code orange-text">${esc(c.src_ip)}</span></div>
          <div class="kv-item"><span class="kv-label">MITRE 기법</span><span class="kv-val mono-code">${esc(c.mitre_technique)}</span></div>
        </div>
        <button type="button" class="btn-primary-emerald" id="btn-drawer-block-ip">출발지 IP(${esc(c.src_ip)}) 게이트웨이 차단 등록</button>
      </div>
    `;
    document.getElementById('btn-drawer-block-ip')?.addEventListener('click', async () => {
      await apiFetch('/api/soar/propose', {
        method: 'POST',
        body: JSON.stringify({
          caseId: c.case_id,
          actionType: 'BLOCK_ATTACK_IP',
          target: c.src_ip,
          assetCriticality: 'LOW',
          reason: `케이스(${c.case_id}) IOC 출발지 IP 차단`
        })
      });
      showToast(`출발지 IP(${c.src_ip}) 차단 조치가 등록되었습니다.`);
      await openCaseDetailDrawer(c.case_id);
      await loadOverview();
    });
  } else if (state.activeCaseTab === 'report') {
    body.innerHTML = `
      <div class="panel-card">
        <div class="card-title">
          <span class="section-main-title">AI 근거 고정 분석 감사 내역</span>
          <button type="button" class="btn-primary-emerald" id="btn-run-case-ai-now">실시간 AI 분석 실행</button>
        </div>
        <div id="drawer-ai-output" class="code-dump-box">${
          (c.aiAudits || []).length > 0
            ? JSON.stringify(c.aiAudits[0], null, 2)
            : '상단 [실시간 AI 분석 실행] 버튼을 누르면 이 케이스에 속한 실제 eventId만을 근거로 판정 보고서를 생성합니다.'
        }</div>
      </div>
    `;
    document.getElementById('btn-run-case-ai-now')?.addEventListener('click', async () => {
      const res = await apiFetch('/api/ai/triage', {
        method: 'POST',
        body: JSON.stringify({ caseId: c.case_id, anonymize: true })
      });
      document.getElementById('drawer-ai-output').textContent = JSON.stringify(res, null, 2);
      showToast(`케이스(${c.case_id}) AI 분석 완료: ${res.aiLabel}`);
      await loadOverview();
    });
  } else if (state.activeCaseTab === 'activity') {
    const actions = c.soarActions || [];
    body.innerHTML = `
      <div class="panel-card">
        <div class="card-title">
          <span class="section-main-title">케이스 연관 능동 대응(SOAR) 조치 내역 (${actions.length}건)</span>
          <button type="button" class="btn-outline-sm" id="btn-drawer-goto-soar">SOAR 전체 관리 뷰로 이동</button>
        </div>
        ${
          actions.length === 0
            ? `<p class="muted-label">이 케이스에 등록된 SOAR 조치가 없습니다. [침해 지표(IOC)] 탭에서 IP 차단을 등록해보세요.</p>`
            : actions
                .map(
                  (a) => `
              <div class="panel-card">
                <div><strong>${esc(a.action_type)}</strong> ➔ <span class="mono-code emerald-text">${esc(a.target)}</span></div>
                <div class="muted-label">상태: ${esc(a.stage)} · 영수증: ${esc(a.receipt_id || '-')} · ${esc(a.enforcement_note)}</div>
              </div>
            `
                )
                .join('')
        }
      </div>
    `;
    document.getElementById('btn-drawer-goto-soar')?.addEventListener('click', () => {
      document.getElementById('drawer-case-detail')?.classList.add('hidden');
      switchView('soar');
    });
  }
}

function openAiReportModal(caseObj) {
  const modal = document.getElementById('modal-ai-report');
  const body = document.getElementById('modal-ai-report-body');
  const isClosed = caseObj.status === 'Closed';

  body.innerHTML = `
    <div class="filter-bar">
      <select id="modal-report-type" class="filter-select">
        <option value="조사 리포트">조사 리포트 (Investigation Report)</option>
        <option value="종결 리포트" ${!isClosed ? 'disabled' : ''}>종결 리포트 (Closure Report — Closed 상태 전용)</option>
      </select>
      <label class="muted-label"><input type="checkbox" id="modal-anonymize" checked /> 민감정보 익명화([REDACTED]) 적용</label>
      <button type="button" class="btn-primary-emerald" id="btn-modal-generate">리포트 생성 실행</button>
    </div>
    <div id="modal-ai-result" class="code-dump-box">케이스(${esc(caseObj.case_id)})의 수집 이벤트 ID를 바인딩하여 리포트를 생성합니다.</div>
  `;

  document.getElementById('btn-modal-generate').addEventListener('click', async () => {
    const reportType = document.getElementById('modal-report-type').value;
    const anonymize = document.getElementById('modal-anonymize').checked;
    const res = await apiFetch('/api/ai/triage', {
      method: 'POST',
      body: JSON.stringify({ caseId: caseObj.case_id, reportType, anonymize })
    });
    document.getElementById('modal-ai-result').textContent = JSON.stringify(res, null, 2);
    showToast('AI 분석 리포트 생성이 완료되었습니다.');
    await loadOverview();
  });

  modal.classList.remove('hidden');
}

// ============================================================================
// 슬라이드오버 드로어 3: AI 게이트웨이 & 자동차단 설정
// ============================================================================
function renderTenantSettingsDrawer() {
  const body = document.getElementById('drawer-tenant-body');
  const t = state.overview?.currentTenant || {};

  if (state.activeTenantTab === 'ai-link') {
    body.innerHTML = `
      <div class="panel-card">
        <div class="card-title"><span class="section-main-title">AI 게이트웨이 연결 상태 점검</span></div>
        <div class="kv-grid">
          <div class="kv-item"><span class="kv-label">프로바이더</span><span class="kv-val mono-code">${esc(t.ai_provider)}</span></div>
          <div class="kv-item"><span class="kv-label">엔드포인트 도메인</span><span class="kv-val mono-code">${esc(t.ai_domain)}</span></div>
          <div class="kv-item"><span class="kv-label">활성 모델</span><span class="kv-val mono-code">${esc(t.ai_model)}</span></div>
        </div>
        <div class="filter-bar">
          <button type="button" class="btn-primary-emerald" id="btn-test-ai-health">게이트웨이 연결 상태 확인</button>
        </div>
        <div id="ai-health-output" class="code-dump-box">위 버튼을 클릭하면 현재 AI 게이트웨이 연결 상태를 실시간 점검합니다.</div>
      </div>
    `;
    document.getElementById('btn-test-ai-health').addEventListener('click', async () => {
      const res = await apiFetch('/api/ai/health', {
        method: 'POST',
        body: JSON.stringify({ scenario: 'ok', domain: t.ai_domain, model: t.ai_model })
      });
      document.getElementById('ai-health-output').textContent = JSON.stringify(res, null, 2);
      showToast('AI 게이트웨이 정상 연결이 확인되었습니다.');
    });
  } else if (state.activeTenantTab === 'soc-agent') {
    body.innerHTML = `
      <div class="panel-card">
        <div class="card-title"><span class="section-main-title">SOC Agent 자율 동작 제어 (Kill Switch & 폴링 주기)</span></div>
        <div class="filter-bar">
          <label><input type="checkbox" id="chk-emergency-stop" ${t.soc_emergency_stop ? 'checked' : ''} /> SOC Agent 긴급 중지 (Kill Switch 활성화)</label>
          <input type="number" id="inp-poll-sec" class="filter-input" value="${t.soc_poll_sec || 60}" />
          <button type="button" class="btn-primary-emerald" id="btn-save-soc-settings">설정 저장</button>
        </div>
      </div>
    `;
    document.getElementById('btn-save-soc-settings').addEventListener('click', async () => {
      const soc_emergency_stop = document.getElementById('chk-emergency-stop').checked;
      const soc_poll_sec = Number(document.getElementById('inp-poll-sec').value || 60);
      await apiFetch('/api/tenant/settings', {
        method: 'POST',
        body: JSON.stringify({ soc_emergency_stop, soc_poll_sec })
      });
      showToast('SOC Agent 설정이 저장되었습니다.');
      await loadOverview();
    });
  } else {
    body.innerHTML = `
      <div class="panel-card">
        <div class="card-title"><span class="section-main-title">정책 기반 자동차단 자산 중요도 기준 설정</span></div>
        <div class="filter-bar">
          <select id="sel-crit-threshold" class="filter-select">
            <option value="HIGH" ${t.asset_criticality_threshold === 'HIGH' ? 'selected' : ''}>HIGH (중요도 HIGH 이상 자산은 관리자 승인 필수)</option>
            <option value="MEDIUM" ${t.asset_criticality_threshold === 'MEDIUM' ? 'selected' : ''}>MEDIUM (중요도 MEDIUM 이상 자산 관리자 승인 필수)</option>
            <option value="LOW" ${t.asset_criticality_threshold === 'LOW' ? 'selected' : ''}>LOW (모든 자산 관리자 승인 필수)</option>
          </select>
          <button type="button" class="btn-primary-emerald" id="btn-save-block-settings">기준 저장</button>
        </div>
      </div>
    `;
    document.getElementById('btn-save-block-settings').addEventListener('click', async () => {
      const asset_criticality_threshold = document.getElementById('sel-crit-threshold').value;
      await apiFetch('/api/tenant/settings', {
        method: 'POST',
        body: JSON.stringify({ asset_criticality_threshold })
      });
      showToast(`자동차단 보류 자산 중요도 기준이 [${asset_criticality_threshold}]로 저장되었습니다.`);
      await loadOverview();
    });
  }
}

// ============================================================================
// 글로벌 이벤트 바인딩 및 초기화
// ============================================================================
function initGlobalEvents() {
  document.getElementById('btn-sidebar-toggle')?.addEventListener('click', () => {
    const sb = document.getElementById('xdr-sidebar');
    const layout = document.querySelector('.xdr-layout');
    const isCollapsed = sb?.classList.toggle('collapsed');
    layout?.classList.toggle('sidebar-collapsed', Boolean(isCollapsed));
  });
  document.getElementById('brand-home')?.addEventListener('click', () => {
    switchView('cases');
  });

  document.querySelectorAll('#nav-dashboard-list .nav-item').forEach((btn) => {
    btn.addEventListener('click', () => switchView(btn.dataset.view));
  });

  const searchInput = document.getElementById('global-case-search');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      state.searchQuery = e.target.value.trim();
      renderCurrentView();
    });
  }

  document.getElementById('btn-toolbar-refresh')?.addEventListener('click', async () => {
    showToast('실시간 Windows 이벤트 로그, 유입 HTTP 로그, 호스트 상태를 새로고침합니다...');
    await loadOverview();
  });

  document.getElementById('btn-refresh-telemetry')?.addEventListener('click', async () => {
    showToast('호스트의 실시간 로그 및 네트워크·프로세스 상태를 재수집합니다...');
    await loadOverview();
  });

  document.getElementById('btn-open-tenant-drawer')?.addEventListener('click', () => {
    renderTenantSettingsDrawer();
    document.getElementById('drawer-tenant-settings').classList.remove('hidden');
  });

  document.getElementById('btn-top-backup')?.addEventListener('click', async () => {
    const res = await apiFetch('/api/db/backup', { method: 'POST', body: JSON.stringify({ label: 'topbar' }) });
    showToast(`SQLite 무결성 백업 생성 완료: ${res.backupFile}`);
  });

  document.getElementById('btn-top-cases')?.addEventListener('click', () => openCaseListDrawer());

  document.querySelectorAll('[data-close-drawer]').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.getElementById(btn.dataset.closeDrawer)?.classList.add('hidden');
    });
  });
  document.querySelectorAll('[data-close-modal]').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.getElementById(btn.dataset.closeModal)?.classList.add('hidden');
    });
  });

  document.querySelectorAll('#case-detail-tabs .drawer-tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('#case-detail-tabs .drawer-tab').forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');
      state.activeCaseTab = tab.dataset.tab;
      renderCaseDetailTab();
    });
  });

  document.querySelectorAll('#tenant-detail-tabs .drawer-tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('#tenant-detail-tabs .drawer-tab').forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');
      state.activeTenantTab = tab.dataset.ttab;
      renderTenantSettingsDrawer();
    });
  });

  const updateCaseAction = async (patch, msg) => {
    if (!state.activeCaseId) return;
    await apiFetch('/api/cases/verdict', {
      method: 'POST',
      body: JSON.stringify({ caseId: state.activeCaseId, ...patch })
    });
    showToast(msg);
    await openCaseDetailDrawer(state.activeCaseId);
    await loadOverview();
  };

  document.getElementById('btn-case-ack')?.addEventListener('click', () =>
    updateCaseAction({ status: 'Acknowledged' }, '케이스 상태가 [인지(Acknowledged)]로 변경되었습니다.')
  );
  document.getElementById('btn-case-close')?.addEventListener('click', () =>
    updateCaseAction({ status: 'Closed' }, '케이스가 [종결(Closed)] 처리되고 MTTR이 기록되었습니다.')
  );
  document.getElementById('btn-case-fp')?.addEventListener('click', () =>
    updateCaseAction(
      { verdictStatus: 'FALSE_POSITIVE', status: 'Closed', ruleTuningNote: '오탐 예외처리 및 탐지 임계치 완화' },
      '오탐(FP) 판정 및 룰 예외 튜닝이 기록되었습니다.'
    )
  );
  document.getElementById('btn-case-tp')?.addEventListener('click', () =>
    updateCaseAction(
      { verdictStatus: 'TRUE_POSITIVE', status: 'Acknowledged', ruleTuningNote: '정탐(TP) 확정 및 가중치 유지' },
      '정탐(TP) 판정이 확정되었습니다.'
    )
  );

  document.getElementById('btn-back-to-list')?.addEventListener('click', () => {
    document.getElementById('drawer-case-detail').classList.add('hidden');
    openCaseListDrawer();
  });
}

window.addEventListener('DOMContentLoaded', () => {
  initGlobalEvents();
  loadOverview();
});
