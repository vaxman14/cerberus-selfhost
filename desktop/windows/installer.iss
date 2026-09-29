#define StageDir GetEnv("CERBERUS_STAGE_DIR")
#define OutputDir GetEnv("CERBERUS_INSTALLER_DIR")
#define AppVersion GetEnv("CERBERUS_VERSION")

[Setup]
AppId={{0AA4D8A4-2A98-4B82-A936-4BF9C4CDAD04}
AppName=Cerberus
AppVersion={#AppVersion}
AppPublisher=CTF Designs
AppPublisherURL=https://cerberusscan.com
AppSupportURL=https://cerberusscan.com/help
DefaultDirName={localappdata}\Programs\Cerberus
DefaultGroupName=Cerberus
OutputDir={#OutputDir}
OutputBaseFilename=Cerberus-Windows-{#AppVersion}-x64-Setup
Compression=lzma2/ultra64
SolidCompression=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
UninstallDisplayName=Cerberus
VersionInfoVersion={#AppVersion}.0
VersionInfoCompany=CTF Designs
VersionInfoDescription=Cerberus website security scanner
VersionInfoProductName=Cerberus

[Files]
Source: "{#StageDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Cerberus"; Filename: "{app}\Cerberus.exe"
Name: "{autodesktop}\Cerberus"; Filename: "{app}\Cerberus.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
Filename: "{app}\Cerberus.exe"; Description: "Launch Cerberus"; Flags: nowait postinstall skipifsilent
