# Log Analyzer Docker Setup (with Requirements Files)

## Included Components
- Frontend (React)
- Backend (Flask API)
- Analyzer (Python)
- MongoDB Database
- docker-compose.yml for integration

## How to Run

1. Install Docker & Docker Compose
2. Clone your repository and go to folder:
   ```bash
   git clone https://github.com/yourname/log-analyzer-docker.git
   cd log-analyzer-docker
   ```
3. Run the setup:
   ```bash
   docker-compose up --build
   ```
4. Open in browser:
   - Frontend → http://localhost:3000
   - Backend → http://localhost:5000
   - MongoDB → localhost:27017
