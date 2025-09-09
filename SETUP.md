# Local Setup Guide for Omap

This guide will help you set up the Omap project for local development on Windows.

## Prerequisites
- [Go](https://golang.org/dl/) (version 1.18 or higher recommended)
- [Node.js & npm](https://nodejs.org/) (for the web frontend)
- [Git](https://git-scm.com/)

## Backend Setup (Go)
1. Clone the repository into a user or data directory (not system folders like C:\WINDOWS\system32):
   ```powershell
   cd D:\  # Or C:\Users\<YourName>\
   git clone <repo-url> Omap
   cd Omap
   ```
2. Build the Go backend:
   ```powershell
   # There are two backend targets:
   # - CLI scanner (root `main.go`) builds `omap.exe` for CLI usage
   go build -o omap.exe main.go

   # - Web UI server (serves frontend build and provides WebSocket/API) lives in `web/server.go`.
   #   Build it when you want to serve the web UI from the Go server:
   go build -o webserver.exe ./web/server.go
   ```
3. Run the backend:
   ```powershell
   # To run the CLI scanner
   .\omap.exe --help

   # To run the Web UI server (serves `web/build` and provides /ws and /api endpoints)
   .\webserver.exe
   ```

## Frontend Setup (React)
1. Navigate to the web directory:
   ```powershell
   cd web
   ```
2. Install dependencies:
   ```powershell
   npm install
   ```
3. Start the development server:
   ```powershell
   npm start
   ```
   The frontend will be available at [http://localhost:3000](http://localhost:3000).

4. Build static assets for production (served by Go webserver):
   ```powershell
   npm run build
   ```

5. Serve the static build with the Go webserver (recommended for local integration):
   - Make sure `web/build` exists (from step 4).
   - Run `webserver.exe` from the project root (it listens on port 8080 by default):
     ```powershell
     cd ..\
     .\webserver.exe
     ```
   - Open http://localhost:8080 to use the Web UI. The client connects to ws://localhost:8080/ws for live updates.

## Optional: Docker Setup
If you prefer using Docker, you can use the provided `Dockerfile` and `docker-compose.yml`.

1. Build and run with Docker Compose:
   ```powershell
   docker-compose up --build
   ```

## Troubleshooting

## Next Steps

If this setup works, the instructions will be merged into `README.md`.
Examples:
   .\omap.exe -t 192.168.1.1 -p 1-1000
   .\omap.exe -t 192.168.1.0/24 -p top-100 --os --sV
   .\omap.exe -t example.com -p 80,443 --plugins
   .\omap.exe --recon -t example.com
   .\omap.exe --recon --recon-mode subdomains -t example.com
   .\omap.exe --recon --recon-verbose --recon-output-file results.json -t example.com
   .\omap.exe 192.168.1.1 1 1000 200
