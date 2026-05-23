REM ====================================================
REM WARSOC DASHBOARD STARTUP COMMANDS (Windows CMD)
REM ====================================================

REM 1. Start all backend services (MongoDB, Redis, API, Workers, Nginx)
cd c:\Users\Lenovo\Desktop\Startup-backend
docker-compose up -d

REM 2. Check if all services are running
docker-compose ps

REM 3. Check backend logs (API should be listening on port 8000)
docker-compose logs app

REM 4. Test API health
curl http://localhost:8000/health

REM 5. Open dashboard in browser
start http://localhost:3000

REM ====================================================
REM Dashboard Access Points
REM ====================================================
REM Frontend Dashboard:  http://localhost:3000
REM Backend API:         http://localhost:8000
REM Nginx Proxy:         http://localhost
REM MongoDB:             localhost:27017
REM Redis CLI:           redis-cli -h localhost -p 6379
