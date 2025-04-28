# Migrate2WinSSHTerm
This project will help you to migrate your existing remote configuration to [WinSSHTerm](https://github.com/WinSSHTerm/WinSSHTerm).

Following configuration sources are supported:

| Source                   | SSH | RDP | VNC |
|--------------------------|-----|-----|-----|
| PuTTY                    | yes | no  | no  |
| PuTTY Session Manager    | yes | no  | no  |
| MobaXterm                | yes | yes | yes |
| SuperPuTTY               | yes | no  | no  |
| mRemoteNG                | yes | yes | yes |
| MTPuTTY                  | yes | no  | no  |
| PuTTY Connection Manager | yes | no  | no  |
| KiTTY                    | yes | no  | no  |
| Xshell                   | yes | no  | no  |
| SecureCRT                | yes | no  | no  |
| Royal TS                 | yes | yes | yes |

Usage:
* Make sure that the latest [Microsoft Visual C++ Redistributable package](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170#latest-microsoft-visual-c-redistributable-version) (X64) is installed
* Download the latest [release](https://github.com/P-St/Migrate2WinSSHTerm/releases)
* Extract the zip file
* To generate the connections.xml just double-click Migrate2WinSSHTerm.exe
* Place the connections.xml into the folder WinSSHTerm/config/. If you use the installer version of WinSSHTerm this folder is inside your Documents folder.
