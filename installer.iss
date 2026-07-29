[Setup]
AppName=WarSOC Agent
AppVersion=4.2.7
DefaultDirName={commonpf}\WarSOC
DefaultGroupName=WarSOC
OutputBaseFilename=warsoc_installer-4.2.7
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
DisableProgramGroupPage=yes

[Files]
Source: "agent\dist\warsoc_agent.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "tools\nssm\nssm.exe"; DestDir: "{app}\bin"; DestName: "nssm.exe"; Flags: ignoreversion
Source: "agent\tenant_policy.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "agent\deploy_warsoc_telemetry.ps1"; DestDir: "{app}"; Flags: ignoreversion; AfterInstall: ConfigureTelemetryAndAgent

[Dirs]
Name: "{app}\logs"

[Run]
Filename: "{app}\bin\nssm.exe"; Parameters: "stop WarSOC_Agent"; Flags: runhidden; StatusMsg: "Stopping existing WarSOC Agent service..."; Check: ServiceExists
Filename: "{app}\bin\nssm.exe"; Parameters: "remove WarSOC_Agent confirm"; Flags: runhidden; StatusMsg: "Removing existing WarSOC Agent service..."; Check: ServiceExists
Filename: "{app}\bin\nssm.exe"; Parameters: "install WarSOC_Agent ""{app}\warsoc_agent.exe"""; Flags: runhidden; StatusMsg: "Installing WarSOC Agent service..."
Filename: "{app}\bin\nssm.exe"; Parameters: "set WarSOC_Agent AppDirectory ""{app}"""; Flags: runhidden
Filename: "{app}\bin\nssm.exe"; Parameters: "set WarSOC_Agent AppStdout ""{app}\logs\warsoc_agent.out.log"""; Flags: runhidden
Filename: "{app}\bin\nssm.exe"; Parameters: "set WarSOC_Agent AppStderr ""{app}\logs\warsoc_agent.err.log"""; Flags: runhidden
Filename: "{app}\bin\nssm.exe"; Parameters: "set WarSOC_Agent AppRotateFiles 1"; Flags: runhidden
Filename: "{app}\bin\nssm.exe"; Parameters: "set WarSOC_Agent AppRotateOnline 1"; Flags: runhidden
Filename: "{app}\bin\nssm.exe"; Parameters: "set WarSOC_Agent AppRotateBytes 10485760"; Flags: runhidden
Filename: "{app}\bin\nssm.exe"; Parameters: "set WarSOC_Agent AppExit Default Restart"; Flags: runhidden
Filename: "{app}\bin\nssm.exe"; Parameters: "set WarSOC_Agent Start SERVICE_AUTO_START"; Flags: runhidden
Filename: "{app}\bin\nssm.exe"; Parameters: "start WarSOC_Agent"; Flags: runhidden; StatusMsg: "Starting WarSOC Agent service..."

[UninstallRun]
Filename: "{app}\bin\nssm.exe"; Parameters: "stop WarSOC_Agent"; Flags: runhidden; RunOnceId: "StopWarSOCAgent"; Check: ServiceExists
Filename: "{app}\bin\nssm.exe"; Parameters: "remove WarSOC_Agent confirm"; Flags: runhidden; RunOnceId: "RemoveWarSOCAgent"; Check: ServiceExists
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ""{app}\deploy_warsoc_telemetry.ps1"" -Rollback"; Flags: runhidden waituntilterminated; RunOnceId: "RollbackWarSOCNativeTelemetry"

[Code]
var
  Token: String;
  BackendUrl: String;
  PosPaths: String;
  ActivationPage: TInputQueryWizardPage;

function ServiceExists: Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec(ExpandConstant('{app}\bin\nssm.exe'), 'status WarSOC_Agent', '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
    and (ResultCode = 0);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
  NssmPath: String;
begin
  Result := '';
  NssmPath := ExpandConstant('{app}\bin\nssm.exe');

  if FileExists(NssmPath) then
  begin
    Exec(NssmPath, 'stop WarSOC_Agent', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(NssmPath, 'remove WarSOC_Agent confirm', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;

  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /T /IM warsoc_agent.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(1000);
end;

procedure InitializeWizard;
begin
  ActivationPage := CreateInputQueryPage(
    wpSelectDir,
    'WarSOC Agent Activation',
    'Enter the activation details supplied by your WarSOC dashboard.',
    'Paste the activation code and confirm the backend URL.'
  );
  ActivationPage.Add('Activation code:', False);
  ActivationPage.Add('Backend URL:', False);
  ActivationPage.Add('POS directories (optional, comma or semicolon separated):', False);
  ActivationPage.Values[1] := 'https://api.warsoc.tech';

  { Pre-fill unattended deployment values before NextButtonClick validates the page. }
  if ExpandConstant('{param:ACTIVATION_CODE}') <> '' then
    ActivationPage.Values[0] := ExpandConstant('{param:ACTIVATION_CODE}');
  if ExpandConstant('{param:TOKEN}') <> '' then
    ActivationPage.Values[0] := ExpandConstant('{param:TOKEN}');
  if ExpandConstant('{param:BACKEND_URL}') <> '' then
    ActivationPage.Values[1] := ExpandConstant('{param:BACKEND_URL}');
  if ExpandConstant('{param:POS_PATHS}') <> '' then
    ActivationPage.Values[2] := ExpandConstant('{param:POS_PATHS}');
end;

function TrimTrailingSlash(Value: String): String;
begin
  Result := Trim(Value);
  while (Length(Result) > 0) and (Copy(Result, Length(Result), 1) = '/') do
    Delete(Result, Length(Result), 1);
end;

function JsonEscape(Value: String): String;
begin
  Result := Value;
  StringChangeEx(Result, '\', '\\', True);
  StringChangeEx(Result, '"', '\"', True);
end;

function IsActivationCodeFormatValid(Value: String): Boolean;
var
  Code: String;
  i: Integer;
  Ch: String;
begin
  Code := Uppercase(Trim(Value));
  Result := False;
  if Length(Code) <> 15 then
    Exit;
  if Copy(Code, 1, 7) <> 'WARSOC-' then
    Exit;
  for i := 8 to 15 do
  begin
    Ch := Copy(Code, i, 1);
    if Pos(Ch, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') = 0 then
      Exit;
  end;
  Result := True;
end;

function IsBackendUrlAllowed(Value: String): Boolean;
var
  Url: String;
begin
  Url := Lowercase(Trim(Value));
  Result :=
    (Pos('https://', Url) = 1) or
    (Pos('http://127.0.0.1', Url) = 1) or
    (Pos('http://localhost', Url) = 1);
end;

function ValidateActivationCode(ActivationCode: String; ApiBaseUrl: String): Boolean;
var
  Http: Variant;
  RequestUrl: String;
  Body: String;
begin
  Result := False;
  RequestUrl := TrimTrailingSlash(ApiBaseUrl) + '/api/v1/agent/validate-activation';
  Body := '{"activation_code":"' + JsonEscape(Uppercase(Trim(ActivationCode))) + '"}';

  try
    Http := CreateOleObject('WinHttp.WinHttpRequest.5.1');
    Http.SetTimeouts(5000, 5000, 10000, 10000);
    Http.Open('POST', RequestUrl, False);
    Http.SetRequestHeader('Content-Type', 'application/json');
    Http.Send(Body);

    if Http.Status = 200 then
    begin
      Result := True;
      Exit;
    end;

    MsgBox(
      'WarSOC rejected this activation code. Generate a fresh activation code from the dashboard and try again.' + #13#10#13#10 +
      'Server response: HTTP ' + IntToStr(Http.Status),
      mbError,
      MB_OK
    );
  except
    MsgBox(
      'The installer could not contact the WarSOC backend to validate activation.' + #13#10#13#10 +
      'Check the backend URL and internet connectivity, then try again.',
      mbError,
      MB_OK
    );
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID <> ActivationPage.ID then
    Exit;

  Token := Uppercase(Trim(ActivationPage.Values[0]));
  BackendUrl := TrimTrailingSlash(ActivationPage.Values[1]);

  if not IsActivationCodeFormatValid(Token) then
  begin
    MsgBox('Enter a valid WarSOC activation code in the format WARSOC-XXXXXXXX.', mbError, MB_OK);
    Result := False;
    Exit;
  end;

  if not IsBackendUrlAllowed(BackendUrl) then
  begin
    MsgBox('Backend URL must use HTTPS in production. Local HTTP is only allowed for 127.0.0.1 or localhost testing.', mbError, MB_OK);
    Result := False;
    Exit;
  end;

  ActivationPage.Values[0] := Token;
  ActivationPage.Values[1] := BackendUrl;

  if not ValidateActivationCode(Token, BackendUrl) then
  begin
    Result := False;
    Exit;
  end;
end;

procedure ConfigureTelemetryAndAgent;
var
  ConfigFile: String;
  ConfigContent: TArrayOfString;
  EnvFile: String;
  Lines: TArrayOfString;
  i: Integer;
  ResultCode: Integer;
  PowerShellPath: String;
  TelemetryScript: String;
  TelemetryArgs: String;
begin
  Token := '';
  BackendUrl := '';

  { Read from Command Line }
  if ExpandConstant('{param:ACTIVATION_CODE}') <> '' then
    Token := ExpandConstant('{param:ACTIVATION_CODE}');
  if ExpandConstant('{param:TOKEN}') <> '' then
    Token := ExpandConstant('{param:TOKEN}');
  if ExpandConstant('{param:BACKEND_URL}') <> '' then
    BackendUrl := ExpandConstant('{param:BACKEND_URL}');
  if ExpandConstant('{param:POS_PATHS}') <> '' then
    PosPaths := ExpandConstant('{param:POS_PATHS}');

  { Read from the activation wizard page }
  if (Token = '') and (ActivationPage.Values[0] <> '') then
    Token := ActivationPage.Values[0];
  if (BackendUrl = '') and (ActivationPage.Values[1] <> '') then
    BackendUrl := ActivationPage.Values[1];
  if (PosPaths = '') and (ActivationPage.Values[2] <> '') then
    PosPaths := ActivationPage.Values[2];

  { Fallback to .env in installer directory }
  if (Token = '') or (BackendUrl = '') then
  begin
    EnvFile := ExpandConstant('{src}\.env');
    if LoadStringsFromFile(EnvFile, Lines) then
    begin
      for i := 0 to GetArrayLength(Lines) - 1 do
      begin
        if Pos('ACTIVATION_CODE=', Lines[i]) = 1 then
          Token := Trim(Copy(Lines[i], 17, Length(Lines[i])));
        if Pos('BACKEND_URL=', Lines[i]) = 1 then
          BackendUrl := Trim(Copy(Lines[i], 13, Length(Lines[i])));
      end;
    end;
  end;

  if Token = '' then
    RaiseException('An activation code is required.');
  if BackendUrl = '' then
    RaiseException('A backend URL is required.');
  Token := Uppercase(Trim(Token));
  BackendUrl := TrimTrailingSlash(BackendUrl);
  if not IsActivationCodeFormatValid(Token) then
    RaiseException('Activation code format is invalid. Expected WARSOC-XXXXXXXX.');
  if not IsBackendUrlAllowed(BackendUrl) then
    RaiseException('Backend URL must use HTTPS in production. Local HTTP is only allowed for 127.0.0.1 or localhost testing.');
  if not ValidateActivationCode(Token, BackendUrl) then
    RaiseException('Activation validation failed. Installation aborted before service startup.');

  { Generate the installed config files }
  ConfigFile := ExpandConstant('{app}\.env');
  SetArrayLength(ConfigContent, 4);
  ConfigContent[0] := 'TENANT_ID=provision';
  ConfigContent[1] := 'AGENT_ID=auto';
  ConfigContent[2] := 'BACKEND_URL=' + BackendUrl;
  ConfigContent[3] := 'ACTIVATION_CODE=' + Token;
  SaveStringsToFile(ConfigFile, ConfigContent, False);

  if not Exec(
    ExpandConstant('{sys}\icacls.exe'),
    '"' + ConfigFile + '" /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F"',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  ) then
    RaiseException('Unable to secure the agent activation environment file.');
  if ResultCode <> 0 then
    RaiseException('Securing the agent activation environment file failed with exit code ' + IntToStr(ResultCode) + '.');

  PowerShellPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  TelemetryScript := ExpandConstant('{app}\deploy_warsoc_telemetry.ps1');
  TelemetryArgs := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
    TelemetryScript + '"';
  if PosPaths <> '' then
    TelemetryArgs := TelemetryArgs + ' -PosPaths "' + PosPaths + '"';

  if not Exec(PowerShellPath, TelemetryArgs, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    RaiseException('Unable to start native Windows telemetry configuration.');
  if ResultCode <> 0 then
    RaiseException('Native Windows telemetry configuration failed with exit code ' + IntToStr(ResultCode) + '.');
end;
