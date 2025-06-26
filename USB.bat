@echo off
cd %~dp0
setlocal EnableExtensions DisableDelayedExpansion

::ASPM
echo info: aspm
set "base=HKLM\SYSTEM\DriverDatabase\DriverPackages"
for /F "tokens=*" %%D in ('reg query "%base%" 2^>nul') do (
for /F "tokens=*" %%C in ('reg query "%%D\Configurations" 2^>nul') do (
"%WinDir%\NSudoLC.exe" -ShowWindowMode:Hide -U:T -P:E reg add "%%C\Device\e5b3b5ac-9725-4f78-963f-03dfb1d828c7" /v "ASPMOptIn" /t REG_DWORD /d "0" /f
"%WinDir%\NSudoLC.exe" -ShowWindowMode:Hide -U:T -P:E reg add "%%C\Device\e5b3b5ac-9725-4f78-963f-03dfb1d828c7" /v "ASPMOptOut" /t REG_DWORD /d "1" /f
"%WinDir%\NSudoLC.exe" -ShowWindowMode:Hide -U:T -P:E reg add "%%C\Device\e5b3b5ac-9725-4f78-963f-03dfb1d828c7" /v "D3ColdSupported" /t REG_DWORD /d "0" /f
	)
)
set "base2=HKLM\SYSTEM\CurrentControlSet\Enum\PCI"
for /F "tokens=*" %%D in ('reg query "%base2%" 2^>nul') do (
    for /F "tokens=*" %%C in ('reg query "%%D" 2^>nul') do (
"%WinDir%\NSudoLC.exe" -ShowWindowMode:Hide -U:T -P:E reg add "%%C\Device Parameters\e5b3b5ac-9725-4f78-963f-03dfb1d828c7" /v "ASPMOptIn" /t REG_DWORD /d "0" /f
"%WinDir%\NSudoLC.exe" -ShowWindowMode:Hide -U:T -P:E reg add "%%C\Device Parameters\e5b3b5ac-9725-4f78-963f-03dfb1d828c7" /v "ASPMOptOut" /t REG_DWORD /d "1" /f
"%WinDir%\NSudoLC.exe" -ShowWindowMode:Hide -U:T -P:E reg add "%%C\Device Parameters\e5b3b5ac-9725-4f78-963f-03dfb1d828c7" /v "D3ColdSupported" /t REG_DWORD /d "0" /f
	)
)

::USB

::Devices Powersaving
powershell -Command "$power_device_enable = Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi; $usb_devices = @('Win32_USBController', 'Win32_USBControllerDevice', 'Win32_USBHub'); foreach ($power_device in $power_device_enable) { $instance_name = $power_device.InstanceName.ToUpper(); foreach ($device in $usb_devices) { foreach ($hub in Get-WmiObject $device) { $pnp_id = $hub.PNPDeviceID; if ($instance_name -like \"*$pnp_id*\") { $power_device.enable = $False; $power_device.psbase.put() }}}}"

for %%a in (
    "DeviceResetNotificationEnabled"
    "EnhancedPowerManagementEnabled"
    "AllowIdleIrpInD3"
    "EnableSelectiveSuspend"
    "DeviceSelectiveSuspended"
    "SelectiveSuspendEnabled"
    "SelectiveSuspendTimeout"
    "SelectiveSuspendOn"
    "WaitWakeEnabled"
    "D3ColdSupported"
    "WdfDirectedPowerTransitionEnable"
    "EnableIdlePowerManagement"
    "IdleInWorkingState"
    "WakeSystemOnConnect"
    "SystemWakeEnabled"
    "IdleTimeoutPeriodInMilliSec"
    "UserSetDeviceIdleEnabled"
    "EnhancedPowerManagementUseMonitor"
    "SuppressInputInCS"
    "SystemInputSuppressionEnabled"
    "WakeScreenOnInputSupport"
    "WdfDirectedPowerTransitionChildrenOptional"
    "WdfDefaultWakeFromSleepState"
    "WdfDefaultIdleInWorkingState"
    "SessionSecurityEnabled"
    "DeviceIdleEnabled"
    "DeviceIdleIgnoreWakeEnable"
    "IdleTimeoutInMS"
    "DefaultIdleState"
    "RemoteWakeEnabled"
) do (
    for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "%%~a" ^| findstr "HKEY"') do (
"%WinDir%\NSudoLC.exe" -ShowWindowMode:Hide -U:T -P:E reg add "%%b" /v "%%~a" /t REG_DWORD /d "0" /f
    )
)

for %%a in (
    "IdleStatesNumber"
    "IdleExitEnergyMicroJoules"
    "IdleExitLatencyMs"
    "IdlePowerMw"
    "IdleTimeLengthMs"
) do (
    for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\Storage" /s /f "%%~a" ^| findstr "HKEY"') do (
"%WinDir%\NSudoLC.exe" -ShowWindowMode:Hide -U:T -P:E reg add "%%b" /v "%%~a" /t REG_DWORD /d "0" /f
    )
)

for %%a in (
    "ImmediateIdle"
    "ConservationIdleTime"
    "PerformanceIdleTime"
    "IdlePowerState"
) do (
    for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class" /s /f "%%~a" ^| findstr "HKEY"') do (
"%WinDir%\NSudoLC.exe" -ShowWindowMode:Hide -U:T -P:E reg add "%%b" /v "%%~a" /t REG_BINARY /d "00000000" /f
    )
)

for /f "tokens=*" %%s in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\usbflags" /S /F "" ^| findstr /ve "(Default)" ^| findstr /v "REG_SZ" ^| findstr /v "End of search"') do (
"%WinDir%\NSudoLC.exe" -ShowWindowMode:Hide -U:T -P:E reg add "%%s" /v "DisableOnSoftRemove" /t REG_DWORD /d "1" /f
"%WinDir%\NSudoLC.exe" -ShowWindowMode:Hide -U:T -P:E reg add "%%s" /v "DisableLPM" /t REG_DWORD /d "1" /f
"%WinDir%\NSudoLC.exe" -ShowWindowMode:Hide -U:T -P:E reg add "%%s" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f
"%WinDir%\NSudoLC.exe" -ShowWindowMode:Hide -U:T -P:E reg add "%%s" /v "D3ColdSupported" /t REG_DWORD /d "0" /f
)

for %%a in (
    "WakeEnabled"
    "WdkSelectiveSuspendEnable"
    "AllowIdleIrpInD3"
    "D3ColdSupported"
) do (
    for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class" /s /f "%%~a" ^| findstr "HKEY"') do (
"%WinDir%\NSudoLC.exe" -ShowWindowMode:Hide -U:T -P:E reg add "%%b" /v "%%~a" /t REG_DWORD /d "0" /f
    )
)

for %%a in (
    "DisableRuntimePowerManagement" 
    "DisableD3Cold"
    "DisableIdlePowerManagement"
    "DevicePowerUpOnS0Entry"
) do (
    for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "%%~a" ^| findstr "HKEY"') do (
"%WinDir%\NSudoLC.exe" -ShowWindowMode:Hide -U:T -P:E reg add "%%b" /v "%%~a" /t REG_DWORD /d "1" /f
    )
)

for %%a in (
    "D3IdleTimeoutInMS"
    "DeviceIdleEnabled"
    "DeviceResetNotificationEnabled"
    "DeviceIdleIgnoreWakeEnable"
    "DefaultIdleState"    
    "AllowIdleIrpInD3"
    "EnhancedPowerManagementEnabled"
    "EnableIdlePowerManagement"
    "WaitWakeEnabled"
    "D3ColdSupported"
    "SelectiveSuspendEnabled"
    "IdleInWorkingState"
    "LogPages"
    "WdfDefaultIdleInWorkingState"
    "WdfDirectedPowerTransitionEnable"
    "WdfDirectedPowerTransitionChildrenOptional"
    "WdfDefaultWakeFromSleepState"
    "SystemInputSuppressionEnabled"
    "EnableHDDParking"
    "WakeScreenOnInputSupport"
) do (
    for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\DriverDatabase\DriverPackages" /s /f "%%~a" ^| findstr "HKEY"') do (
"%WinDir%\NSudoLC.exe" -ShowWindowMode:Hide -U:T -P:E reg add "%%b" /v "%%~a" /t REG_DWORD /d "0" /f
    )
)

for %%a in (
    "HcDisableSelectiveSuspend"
) do (
    for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\DriverDatabase\DriverPackages" /s /f "%%~a" ^| findstr "HKEY"') do (
"%WinDir%\NSudoLC.exe" -ShowWindowMode:Hide -U:T -P:E reg add "%%b" /v "%%~a" /t REG_DWORD /d "1" /f
    )
)

for %%a in (
    "SelectiveSuspendEnabled"
) do (
    for /f "delims=" %%b in ('reg query "HKLM\SYSTEM\DriverDatabase\DriverPackages" /s /f "%%~a" ^| findstr "HKEY"') do (
"%WinDir%\NSudoLC.exe" -ShowWindowMode:Hide -U:T -P:E reg add "%%b" /v "%%~a" /t REG_BINARY /d "00" /f
    )
)

Exit
