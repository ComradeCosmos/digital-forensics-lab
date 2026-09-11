@echo off
echo ========================================================
echo   Digital Forensics Lab - WSL Kali Linux Runner
echo   Environment configured by: Subham Biswas
echo ========================================================
echo.
echo Launching Kali Linux WSL in digital-forensics-lab workspace...
wsl -d kali-linux -e bash -c "cd /mnt/c/Users/alkes/.gemini/antigravity-ide/scratch/digital-forensics-lab && exec bash"
