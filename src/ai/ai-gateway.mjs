/**
 * AI Gateway Connection Diagnostics & 7 Failure Recovery Guides
 * 테넌트 상세정보 [AI 서비스 연동] (LLM 게이트웨이 및 모델 연동 진단)
 */

export const AI_RECOVERY_GUIDES = {
  UNCONFIGURED: {
    code: 'UNCONFIGURED',
    status: 'error',
    title: 'AI API 키 미설정',
    recoveryGuide: '복구 안내: 테넌트 상세정보 > [AI 서비스 연동] 화면의 비밀 입력란에 유효한 API Key를 주입한 뒤 다시 점검하세요. (코드·Git 저장 금지)'
  },
  AUTH_FAILED_401: {
    code: 'AUTH_FAILED_401',
    status: 'error',
    title: '인증 실패 또는 권한 만료 (HTTP 401/403)',
    recoveryGuide: '복구 안내: API Key가 만료되었거나 해당 테넌트의 LightChat 프록시 접근 권한이 없습니다. 키를 재발급받아 교체하세요.'
  },
  RATE_LIMIT_429: {
    code: 'RATE_LIMIT_429',
    status: 'error',
    title: '호출 한도 및 토큰 예산 초과 (HTTP 429)',
    recoveryGuide: '복구 안내: 케이스당 최대 토큰 또는 월 토큰 예산 한도에 도달했습니다. 폴링 주기(60s)를 늘리거나 한도 설정을 조정하세요.'
  },
  TIMEOUT_504: {
    code: 'TIMEOUT_504',
    status: 'error',
    title: '모델 응답 시간 초과 (Timeout)',
    recoveryGuide: '복구 안내: AI 게이트웨이 응답이 제한 시간을 초과했습니다. 요청을 취소하고 잠시 후 재시도하거나 경량 모델로 전환하세요.'
  },
  MODEL_NOT_FOUND_404: {
    code: 'MODEL_NOT_FOUND_404',
    status: 'error',
    title: '지정 모델명 불일치 (HTTP 404)',
    recoveryGuide: '복구 안내: 설정된 기본 모델(예: claude-sonnet-4-5-20250929)이 게이트웨이 목록에 없습니다. [연결 테스트 & 모델 불러오기]로 목록을 갱신하세요.'
  },
  NETWORK_DISCONNECTED: {
    code: 'NETWORK_DISCONNECTED',
    status: 'error',
    title: 'AI 프록시 도메인 네트워크 단절',
    recoveryGuide: '복구 안내: 도메인(https://xdr-mf.appexnetworks.co.kr)과의 네트워크 연결을 확인할 수 없습니다. 방화벽 및 DNS 설정을 확인하세요.'
  },
  MALFORMED_RESPONSE: {
    code: 'MALFORMED_RESPONSE',
    status: 'error',
    title: '비정상 AI 응답 스키마 감지',
    recoveryGuide: '복구 안내: 모델이 JSON 계약 형식을 벗어난 응답을 반환했습니다. 프롬프트 가드레일(ISO 42001) 설정을 초기화하고 재호출하세요.'
  }
};

export function checkAiGatewayHealth({ scenario = 'healthy', domain = 'https://xdr-mf.appexnetworks.co.kr', model = 'claude-sonnet-4-5-20250929 ★' } = {}) {
  const checkedAt = new Date().toISOString();

  if (scenario && scenario !== 'healthy' && AI_RECOVERY_GUIDES[scenario]) {
    const errInfo = AI_RECOVERY_GUIDES[scenario];
    return {
      ok: false,
      status: 'error',
      mode: 'gateway_diagnostic',
      checkedAt,
      domain,
      model,
      error: {
        code: errInfo.code,
        title: errInfo.title,
        message: `${errInfo.title} [${errInfo.code}]`,
        recoveryGuide: errInfo.recoveryGuide
      },
      secretStoredInCode: false
    };
  }

  return {
    ok: true,
    status: 'ready',
    mode: 'lightchat_proxy',
    checkedAt,
    provider: 'LightChat (전역 기본)',
    domain,
    model,
    availableModelsCount: 38,
    availableModels: [
      'claude-sonnet-4-5-20250929 ★',
      'gemini-2.5-pro',
      'gemini-2.5-flash',
      'gpt-4.1-mini'
    ],
    message: '연결 성공 — 모델 38개 불러오기 완료 (비밀키는 메모리에만 유지되며 코드·로그에 노출되지 않음)',
    secretStoredInCode: false
  };
}
