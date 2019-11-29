; BlackIceConnect PKCS11 by Gradiant Installer
;
; Download NSIS Tool from: http://nsis.sourceforge.net/Descargar
;
;--------------------------------

;Include Modern UI

!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "winmessages.nsh"
!include "logiclib.nsh"
!include "x64.nsh"

;--------------------------------

!system "detect_path.bat"
!include "script_path.nsh"

!define CFG_FILE "BlackICEconnect_win.cnf"

; ------------- 64 bit ---------------------
!define DLL_FILE "BlackICEConnect_x64.dll"
!define ENC_FILE "Encryptconfig_x64.exe" 
!define ICO_FILE "gradiant.ico"
!define ENV_VAR "CRYPTOKI_CNF_64"
!define ARCH "64bit"
; The default installation directory
InstallDir $PROGRAMFILES64\Gradiant\BlackICEConnect_PKCS11
function .onInit
	StrCpy $INSTDIR "$PROGRAMFILES64\Gradiant\BlackICEConnect_PKCS11"	
functionEnd
; The file to write
OutFile "Gradiant_BlackIceConnect_x64_Setup.exe"

; --------------------------------------------

!define MUI_ICON "${SOURCEDIR}\${ICO_FILE}"
!define MUI_UNICON "${SOURCEDIR}\${ICO_FILE}"
;!define MUI_HEADERIMAGE
;!define MUI_HEADERIMAGE_BITMAP "path\to\InstallerLogo.bmp"
;!define MUI_HEADERIMAGE_RIGHT

; The name of the installer
Name "BlackIceConnect PKCS11 by Gradiant"

; Registry key to check for directory (so if you install again, it will 
; overwrite the old one automatically)
InstallDirRegKey HKLM "SOFTWARE\Gradiant_BlackIceConnect_${ARCH}" "Install_Dir"

; Request application privileges for Windows Vista
RequestExecutionLevel admin

;--------------------------------
;Interface Settings

  !define MUI_ABORTWARNING
  !define MUI_CUSTOMFUNCTION_ABORT userAbort

;--------------------------------
;Pages

; !insertmacro MUI_PAGE_LICENSE "${NSISDIR}\Docs\Modern UI\License.txt"
  !insertmacro MUI_PAGE_COMPONENTS
  !insertmacro MUI_PAGE_DIRECTORY
  !insertmacro MUI_PAGE_INSTFILES
  Page Custom settings settingsDone
  !insertmacro MUI_PAGE_FINISH
  
  !insertmacro MUI_UNPAGE_CONFIRM
  !insertmacro MUI_UNPAGE_INSTFILES
  
;--------------------------------
;Languages
 
  !insertmacro MUI_LANGUAGE "English"

!macro _ReplaceInFile SOURCE_FILE SEARCH_TEXT REPLACEMENT
  Push "${SOURCE_FILE}"
  Push "${SEARCH_TEXT}"
  Push "${REPLACEMENT}"
  Call RIF
!macroend  
   
;-------------------------------
;Pages
 
var dialog
var hwnd
var host
var clientid
var tenantid
var passwd
var pin
var timeout
var logpath
var path
var filebutton
var loglevel
var savelog
 
Function Settings
	!insertmacro MUI_HEADER_TEXT "Configuration" "Please enter your Azure Key Vault credentials, a PCKS#11 PIN and log options"
	nsDialogs::Create 1018
	Pop $dialog
    ${NSD_CreateLabel} 0 0 20% 9% "Hostname"
        Pop $hwnd
	${NSD_CreateText} 110 0 75% 9% ""
	    Pop $host
    ${NSD_CreateLabel} 0 30 20% 9% "Client ID"
        Pop $hwnd
	${NSD_CreateText} 110 30 75% 9% ""
	    Pop $clientid
    ${NSD_CreateLabel} 0 60 20% 9% "Tenant ID"
        Pop $hwnd
	${NSD_CreateText} 110 60 75% 9% ""
	    Pop $tenantid
    ${NSD_CreateLabel} 0 90 20% 9% "Password"
        Pop $hwnd		
	${NSD_CreatePassword} 110 90 75% 9% ""
	    Pop $passwd
	    SendMessage $passwd ${EM_SETPASSWORDCHAR} 149 0 # 149 = medium dot
    ${NSD_CreateLabel} 110 120 75% 8% "This Azure credentials will be encrypted with the PKCS#11 PIN"
        Pop $hwnd
    ${NSD_CreateLabel} 0 140 20% 9% "PKCS#11 User PIN"
        Pop $hwnd
	${NSD_CreatePassword} 110 140 30% 9% ""
	    Pop $pin
		SendMessage $pin ${EM_SETPASSWORDCHAR} 149 0 # 149 = medium dot
    ${NSD_CreateLabel} 265 140 25% 9% "Session timeout (min)"
        Pop $hwnd
	${NSD_CreateNumber} 380 140 15% 9% "15"
	    Pop $timeout
    ${NSD_CreateLabel} 0 170 20% 9% "Log path"
        Pop $hwnd		
	${NSD_CreateBrowseButton} 360 169 20% 10% "Browse"
		Pop $filebutton
	${NSD_OnClick} $filebutton FilePathSelector
	${NSD_CreateText} 110 170 55% 9% "$TEMP"
	    Pop $logpath
		;${NSD_Edit_SetReadOnly} $logpath readonly
		SendMessage $logpath ${EM_SETREADONLY} $logpath 0
    ${NSD_CreateLabel} 0 200 20% 9% "Log detail level"
        Pop $hwnd
	${NSD_CreateNumber} 110 200 5% 9% "0"
	    Pop $loglevel	
    ${NSD_CreateLabel} 140 203 45% 8% "(1=Error;2=Warning;3=Info;4=Trace)"
        Pop $hwnd
	${NSD_CreateCheckbox} 350 200 50% 9% "Save log history"
		Pop $savelog
 
	nsDialogs::Show
FunctionEnd
 
Function filePathSelector
	nsDialogs::SelectFolderDialog "Log path" $TEMP
	Pop $path		
	${If} $path != "error"		
		${NSD_SetText} $logpath $path
	${EndIf}
FunctionEnd
 
Function settingsDone    
	${NSD_GetText} $pin $0
	${NSD_GetText} $host $1
	${NSD_GetText} $clientid $2
	${NSD_GetText} $tenantid $3
	${NSD_GetText} $passwd $4
	${NSD_GetText} $timeout $5
	${NSD_GetText} $logpath $6
	${NSD_GetText} $loglevel $7
	${NSD_GetState} $savelog $8

	${If} $1 == ""
		MessageBox MB_OK "Please enter a host name"
		${NSD_SetFocus} $host
		Abort
	${EndIf}
	${If} $2 == ""
		MessageBox MB_OK "Please enter the client ID"
		${NSD_SetFocus} $clientid
		Abort
	${EndIf}
	${If} $3 == ""
		MessageBox MB_OK "Please enter the tenant ID"
		${NSD_SetFocus} $tenantid
		Abort
	${EndIf}
	${If} $4 == ""
		MessageBox MB_OK "Please enter the password"
		${NSD_SetFocus} $passwd
		Abort
	${EndIf}
	StrLen $9 $0
	${If} $0 == ""
	${OrIf} $9 < 4
		MessageBox MB_OK "Please enter a PKCS#11 PIN (minimum 4 characters)"
		${NSD_SetFocus} $pin
		Abort
	${EndIf}
	${If} $6 == ""
		MessageBox MB_OK "Please enter the log file path"
		${NSD_SetFocus} $logpath
		Abort
	${EndIf}
	${If} $7 == ""
	${OrIf} $7 > 4
		MessageBox MB_OK "Please enter a valid log level"
		${NSD_SetFocus} $loglevel
		Abort
	${EndIf}
		
	!insertmacro _ReplaceInFile "$INSTDIR\${CFG_FILE}" "MY_HOST" "$1"
	!insertmacro _ReplaceInFile "$INSTDIR\${CFG_FILE}" "MY_CLIENTID" "$2"
    !insertmacro _ReplaceInFile "$INSTDIR\${CFG_FILE}" "MY_TENANTID" "$3"
	!insertmacro _ReplaceInFile "$INSTDIR\${CFG_FILE}" "MY_PASSWORD" "$4"
	${If} $5 == ""
		!insertmacro _ReplaceInFile "$INSTDIR\${CFG_FILE}" "TIME_OUT" "-1"
	${Else}
		!insertmacro _ReplaceInFile "$INSTDIR\${CFG_FILE}" "TIME_OUT" "$5"	
	${EndIf}
	!insertmacro _ReplaceInFile "$INSTDIR\${CFG_FILE}" "LOG_PATH" "$6"
	!insertmacro _ReplaceInFile "$INSTDIR\${CFG_FILE}" "LOG_LEVEL" "$7"
	!insertmacro _ReplaceInFile "$INSTDIR\${CFG_FILE}" "SAVE_LOG" "$8"
	
	IfFileExists $INSTDIR\${CFG_FILE}.old 0 +2
	Delete $INSTDIR\${CFG_FILE}.old 
	
	;ExecWait 'set ${ENV_VAR}="$INSTDIR\${CFG_FILE}"' $9	
	;SetEnv::SetEnvVar "${ENV_VAR}" "$INSTDIR\${CFG_FILE}"
	;System::Call 'Kernel32::SetEnvironmentVariable(t, t)i ("${ENV_VAR}", "$INSTDIR\${CFG_FILE}").r0'
	ExecWait '"$INSTDIR\${ENC_FILE}" "$INSTDIR\${CFG_FILE}" "$INSTDIR\${DLL_FILE}" "$0"' $9
	;DetailPrint "EncryptConfig returned: $0"
	${If} $9 != 0 
		Delete "$INSTDIR\${CFG_FILE}"
		CopyFiles "$INSTDIR\${CFG_FILE}.template" "$INSTDIR\${CFG_FILE}"
		MessageBox MB_OK "Error encrypting config file: $9"
		Abort
	${EndIf}	
	
	GetDlgItem $0 $HWNDPARENT 3 ; next = 1, cancel = 2, back = 3

	EnableWindow $0 0	
	
FunctionEnd  

Function userAbort
	IfFileExists $INSTDIR\${CFG_FILE} 0 +2
	Delete $INSTDIR\${CFG_FILE}
FunctionEnd
 
;----------------
; Auxiliary functions & macros

!define StrRep "!insertmacro StrRep"
!macro StrRep output string old new
    Push `${string}`
    Push `${old}`
    Push `${new}`
    Call StrRep
    Pop ${output}
!macroend
 
!macro Func_StrRep un
    Function ${un}StrRep
        Exch $R2 ;new
        Exch 1
        Exch $R1 ;old
        Exch 2
        Exch $R0 ;string
        Push $R3
        Push $R4
        Push $R5
        Push $R6
        Push $R7
        Push $R8
        Push $R9
 
        StrCpy $R3 0
        StrLen $R4 $R1
        StrLen $R6 $R0
        StrLen $R9 $R2
        loop:
            StrCpy $R5 $R0 $R4 $R3
            StrCmp $R5 $R1 found
            StrCmp $R3 $R6 done
            IntOp $R3 $R3 + 1 ;move offset by 1 to check the next character
            Goto loop
        found:
            StrCpy $R5 $R0 $R3
            IntOp $R8 $R3 + $R4
            StrCpy $R7 $R0 "" $R8
            StrCpy $R0 $R5$R2$R7
            StrLen $R6 $R0
            IntOp $R3 $R3 + $R9 ;move offset by length of the replacement string
            Goto loop
        done:
 
        Pop $R9
        Pop $R8
        Pop $R7
        Pop $R6
        Pop $R5
        Pop $R4
        Pop $R3
        Push $R0
        Push $R1
        Pop $R0
        Pop $R1
        Pop $R0
        Pop $R2
        Exch $R1
    FunctionEnd
!macroend
!insertmacro Func_StrRep ""

 
Function RIF
 
  ClearErrors  ; want to be a newborn
 
  Exch $0      ; REPLACEMENT
  Exch
  Exch $1      ; SEARCH_TEXT
  Exch 2
  Exch $2      ; SOURCE_FILE
 
  Push $R0     ; SOURCE_FILE file handle
  Push $R1     ; temporary file handle
  Push $R2     ; unique temporary file name
  Push $R3     ; a line to sar/save
  Push $R4     ; shift puffer
 
  IfFileExists $2 +1 RIF_error      ; knock-knock
  FileOpen $R0 $2 "r"               ; open the door
 
  GetTempFileName $R2               ; who's new?
  FileOpen $R1 $R2 "w"              ; the escape, please!
 
  RIF_loop:                         ; round'n'round we go
    FileRead $R0 $R3                ; read one line
    IfErrors RIF_leaveloop          ; enough is enough
    RIF_sar:                        ; sar - search and replace
      Push "$R3"                    ; (hair)stack
      Push "$1"                     ; needle
      Push "$0"                     ; blood
      Call StrRep                   ; do the bartwalk
      StrCpy $R4 "$R3"              ; remember previous state
      Pop $R3                       ; gimme s.th. back in return!
      StrCmp "$R3" "$R4" +1 RIF_sar ; loop, might change again!
    FileWrite $R1 "$R3"             ; save the newbie
  Goto RIF_loop                     ; gimme more
 
  RIF_leaveloop:                    ; over'n'out, Sir!
    FileClose $R1                   ; S'rry, Ma'am - clos'n now
    FileClose $R0                   ; me 2
 
    Delete "$2.old"                 ; go away, Sire
    Rename "$2" "$2.old"            ; step aside, Ma'am
    Rename "$R2" "$2"               ; hi, baby!
 
    ClearErrors                     ; now i AM a newborn
    Goto RIF_out                    ; out'n'away
 
  RIF_error:                        ; ups - s.th. went wrong...
    SetErrors                       ; ...so cry, boy!
 
  RIF_out:                          ; your wardrobe?
  Pop $R4
  Pop $R3
  Pop $R2
  Pop $R1
  Pop $R0
  Pop $2
  Pop $0
  Pop $1
 
FunctionEnd
  
;--------------------------------

;Installer Sections

;--------------------------------

; The stuff to install
Section "BlackIceConnect (required)"

  SectionIn RO
  
  ; Set output path to the installation directory.
  SetOutPath $INSTDIR
  
  ; Put files there
  File "${SOURCEDIR}\${DLL_FILE}"
  File "${SOURCEDIR}\${CFG_FILE}" 
  File "${SOURCEDIR}\${ENC_FILE}"
  File "${SOURCEDIR}\${ICO_FILE}"
  
  ; Write the installation path into the registry
  WriteRegStr HKLM "SOFTWARE\Gradiant_BlackIceConnect_${ARCH}" "Install_Dir" "$INSTDIR"
  
  ; Write the program entries
  ; HKLM (all users) vs HKCU (current user) defines
  WriteRegStr HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "${ENV_VAR}" "$INSTDIR\${CFG_FILE}"
  ;WriteRegStr HKCU "Environment" "${ENV_VAR}" "$INSTDIR\${CFG_FILE}"

  ; make sure windows knows about the change
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000
  
  ; Write the uninstall keys for Windows
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Gradiant_BlackIceConnect_${ARCH}" "DisplayName" "Gradiant_BlackIceConnect_PKCS11"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Gradiant_BlackIceConnect_${ARCH}" "DisplayIcon" "$INSTDIR\${ICO_FILE}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Gradiant_BlackIceConnect_${ARCH}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Gradiant_BlackIceConnect_${ARCH}" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Gradiant_BlackIceConnect_${ARCH}" "NoRepair" 1
  WriteUninstaller "uninstall.exe"
  CopyFiles "$INSTDIR\${CFG_FILE}" "$INSTDIR\${CFG_FILE}.template"
  
SectionEnd

; Optional section (can be disabled by the user)
;Section "Start Menu Shortcuts"

;  CreateDirectory "$SMPROGRAMS\Gradiant\SealSign Client"
;  CreateShortcut "$SMPROGRAMS\Gradiant\SealSign Client\Uninstall.lnk" "$INSTDIR\uninstall.exe" "" "$INSTDIR\uninstall.exe" 0
  
;SectionEnd

;--------------------------------

; Uninstaller

Section "Uninstall"
  
  ; Remove registry keys
  ; HKLM (all users) vs HKCU (current user) defines
  ;DeleteRegValue HKCU "Environment" "${ENV_VAR}"
  DeleteRegValue HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "${ENV_VAR}"
  ; make sure windows knows about the change
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000  
  
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Gradiant_BlackIceConnect_${ARCH}"
  DeleteRegKey HKLM "SOFTWARE\Gradiant_BlackIceConnect_${ARCH}"

  ; Remove files and uninstaller
  Delete $INSTDIR\${DLL_FILE}
  IfFileExists $INSTDIR\${CFG_FILE} 0 +2
  Delete $INSTDIR\${CFG_FILE}
  IfFileExists "$INSTDIR\${CFG_FILE}.template" 0 +2
  Delete "$INSTDIR\${CFG_FILE}.template"
  Delete $INSTDIR\${ENC_FILE}
  Delete $INSTDIR\${ICO_FILE}
  Delete $INSTDIR\uninstall.exe


  ; Remove shortcuts, if any
;  Delete "$SMPROGRAMS\Gradiant\SealSign Client\*.*"

  ; Remove directories used
;  RMDir "$SMPROGRAMS\Gradiant\SealSign Client"
  RMDir "$INSTDIR"

SectionEnd