@echo off
echo ========================================================
echo   Digital Forensics Lab - Containerized Runner
echo   Packaged by: Subham Biswas
echo ========================================================
echo.

echo Building and starting Digital Forensics Lab container...
docker compose up -d --build

echo.
echo ========================================================
echo   Jupyter Lab running at: http://localhost:8888/?token=forensics
echo   To enter interactive bash: docker exec -it digital_forensics_lab bash
echo ========================================================
pause
