cd /d "%~dp0"
set PATH=%~dp0;%PATH%
mklink /d /j "E:\book-code" "H:\rover\rover-self-work\cpp\book-code" 
premake5 --file=projects.lua vs2013
::premake5 --file=projects.lua vs2005
pause