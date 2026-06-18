# CyberSentinel DLP Minifilter - Build Instructions
#
# Prerequisites:
#   - Windows Driver Kit (WDK) 10.0.22621.0 or later
#   - Visual Studio 2022 with C++ desktop development
#   - Windows SDK 10.0.22621.0 or later
#
# Build commands:
#   MSBuild: msbuild csfilter.vcxproj /p:Configuration=Release /p:Platform=x64
#   WDK CLI: build -ceZ
#
# For Visual Studio:
#   1. Open VS Developer Command Prompt
#   2. cd to this directory
#   3. Run: msbuild /p:Configuration=Release /p:Platform=x64
#
# Output: csfilter.sys (copy to %windir%\system32\drivers\)
#
# Installation:
#   sc create CyberSentinelFilter type= filesys binPath= system32\drivers\csfilter.sys
#   sc start CyberSentinelFilter
#   -- OR --
#   fltmc load CyberSentinelFilter
#
# Test signing (development):
#   bcdedit /set testsigning on
#   signtool sign /v /s PrivateCertStore /n "CyberSentinel" csfilter.sys
