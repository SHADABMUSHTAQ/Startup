[Setup]
AppName=WarSOC Agent
AppVersion=1.0
DefaultDirName={commonpf}\WarSOC
DefaultGroupName=WarSOC
OutputBaseFilename=warsoc_installer
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
DisableProgramGroupPage=yes

[Files]
Source: "agent\dist\warsoc_agent.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "tools\nssm\nssm.exe"; DestDir: "{app}\bin"; DestName: "nssm.exe"; Flags: ignoreversion
Source: "agent\tenant_policy.json"; DestDir: "{app}"; Flags: ignoreversion

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

[Code]
var
  Token: String;
  BackendUrl: String;
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
  ActivationPage.Values[1] := 'https://api.warsoc.tech';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ConfigFile: String;
  ConfigContent: TArrayOfString;
  EnvFile: String;
  Lines: TArrayOfString;
  i: Integer;
begin
  if CurStep = ssPostInstall then
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

    { Read from the activation wizard page }
    if (Token = '') and (ActivationPage.Values[0] <> '') then
      Token := ActivationPage.Values[0];
    if (BackendUrl = '') and (ActivationPage.Values[1] <> '') then
      BackendUrl := ActivationPage.Values[1];

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

    { Generate the installed config files }
    ConfigFile := ExpandConstant('{app}\.env');
    SetArrayLength(ConfigContent, 4);
    ConfigContent[0] := 'TENANT_ID=provision';
    ConfigContent[1] := 'AGENT_ID=auto';
    ConfigContent[2] := 'BACKEND_URL=' + BackendUrl;
    ConfigContent[3] := 'ACTIVATION_CODE=' + Token;
    SaveStringsToFile(ConfigFile, ConfigContent, False);

    ConfigFile := ExpandConstant('{app}\config.json');
    SetArrayLength(ConfigContent, 1);
    ConfigContent[0] := '{ "activation_code": "' + Token + '", "backend_url": "' + BackendUrl + '" }';
    SaveStringsToFile(ConfigFile, ConfigContent, False);
  end;
end;
