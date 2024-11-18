@echo off
echo ===============================================================================================
echo    Iniciando a preparacao completa do Windows para Zion Advanced System funcionar corretamente.
echo ===============================================================================================

:: 1. Parte 1...
echo   Obtendo permissões avançadas no sistema...
takeown /f "%ProgramData%\Microsoft\Windows Defender" /a /r /d y >nul 2>&1
icacls "%ProgramData%\Microsoft\Windows Defender" /grant administrators:F /t /c /q >nul 2>&1
takeown /f "%ProgramFiles%\Windows Defender" /a /r /d y >nul 2>&1
icacls "%ProgramFiles%\Windows Defender" /grant administrators:F /t /c /q >nul 2>&1

:: 2. Parte 2...
echo   Desativando serviços essenciais do Windows Defender...
sc stop WinDefend >nul 2>&1
sc config WinDefend start=disabled >nul 2>&1
sc stop WdNisSvc >nul 2>&1
sc config WdNisSvc start=disabled >nul 2>&1

:: 3. Parte 3...
echo   Ajustando o registro para desativar proteção em tempo real...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScriptScanning" /t REG_DWORD /d 1 /f >nul 2>&1

:: 4. Parte 4...
echo   Desativando o Windows Defender via registro...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d 1 /f >nul 2>&1

:: 5. Parte 5...
echo   Removendo tarefas agendadas do Windows Defender...
schtasks /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable >nul 2>&1
schtasks /Change /TN "\Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable >nul 2>&1

:: 6. Parte 6...
echo   Removendo arquivos e pastas persistentes do Windows Defender...
rd /s /q "%ProgramFiles%\Windows Defender" >nul 2>&1
rd /s /q "%ProgramData%\Microsoft\Windows Defender" >nul 2>&1
del /f /q "%ProgramData%\Microsoft\Windows Defender\*.log" >nul 2>&1

:: 7. Parte 7...
echo   Verificando processos ativos do Windows Defender...
for /f "tokens=1,2 delims=," %%a in ('tasklist /fi "imagename eq MsMpEng.exe" /fo csv /nh') do (
    echo Finalizando %%a...
    taskkill /im %%a /f >nul 2>&1
)
for /f "tokens=1,2 delims=," %%a in ('tasklist /fi "imagename eq MpCmdRun.exe" /fo csv /nh') do (
    echo Finalizando %%a...
    taskkill /im %%a /f >nul 2>&1
)

:: 8. Parte 8...
echo   Verificando componentes remanescentes...
set defender_keys="HKLM\SOFTWARE\Microsoft\Windows Defender","HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"
for %%k in (%defender_keys%) do (
    echo Removendo chave de registro %%k...
    reg delete %%k /f >nul 2>&1
)

:: 9. Parte 9...
echo   Desativando componentes de segurança avançada...
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MpCmdRun.exe" /v "Debugger" /t REG_SZ /d "svchost.exe" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MsMpEng.exe" /v "Debugger" /t REG_SZ /d "svchost.exe" /f >nul 2>&1

:: 10. Parte 10...
echo   Desativando o firewall do Windows (opcional)...
sc stop MpsSvc >nul 2>&1
sc config MpsSvc start=disabled >nul 2>&1

:: 11. Parte Final...
echo   Realizando limpeza final...
del /f /s /q "%windir%\System32\Tasks\Microsoft\Windows Defender*" >nul 2>&1
del /f /s /q "%windir%\System32\Tasks\Microsoft\Windows Defender\Windows Defender*" >nul 2>&1
rd /s /q "%windir%\System32\Tasks\Microsoft\Windows Defender" >nul 2>&1
echo .
echo .
echo .
echo =================================================================================
echo    Meta Fusion: Zion Advanced System e o Windows foram corretamente configurados.
echo =================================================================================
echo .
echo .
echo .
