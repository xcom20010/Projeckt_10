@echo off
echo =========================================
echo 🚀 Запуск VirusChecker Python + Go интеграции
echo =========================================

echo 🐍 Запуск Python scanner сервиса...
start /B python scanner.py

timeout /t 3

echo 🔵 Запуск Go веб-сервера...
start /B go run main.go

echo.
echo ✅ Сервисы запущены:
echo   - Python: http://localhost:5000
echo   - Go: http://localhost:8080
echo.
echo Нажмите Ctrl+C для остановки
pause