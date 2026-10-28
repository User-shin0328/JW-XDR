@echo off
chcp 65001 > nul
echo ============================================================================
echo [JW-XDR] Windows 로컬 보안 정책 상시 실증 자동 진단 스크립트
echo  * 주의: 본 스크립트는 읽기 전용(Read-Only)으로만 동작하며 OS 설정을 절대 변경하지 않습니다.
echo ============================================================================
echo.

set OUT_FILE=%TEMP%\jw_xdr_secedit_export.inf

echo [1/3] 레지스트리 기반 LSA / SAM 보안 정책 읽기 전용 조회 (reg query)...
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse 2>nul
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA 2>nul

echo.
echo [2/3] 로컬 보안 정책 템플릿 읽기 전용 덤프 (secedit /export)...
secedit /export /cfg "%OUT_FILE%" /areas SECURITYPOLICY >nul 2>&1
if exist "%OUT_FILE%" (
    echo [실측 성공] secedit 정책 덤프 완료: %OUT_FILE%
    findstr /I "MinimumPasswordLength PasswordComplexity MaximumPasswordAge MinimumPasswordAge LockoutBadCount LockoutDuration EnableGuestAccount NewAdministratorName" "%OUT_FILE%"
) else (
    echo [안내: 일반 권한 실행] 관리자 권한이 없어 secedit 원천 덤프는 제한되었으며, 읽기 전용 net accounts 조회를 수행합니다.
    net accounts
)

echo.
echo [3/3] 진단 완료. 결과는 CloudXDR 컴플라이언스 대시보드에서 수동 점검 체크리스트와 1:1 대조됩니다.
echo ============================================================================
