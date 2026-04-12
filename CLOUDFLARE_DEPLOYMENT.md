# Cloudflare Deployment Guide

## Overview
This guide covers deploying the CyberSec application on Cloudflare. Your FastAPI backend serves the embedded UI, and Cloudflare acts as a reverse proxy with DNS.

## Architecture
```
┌─────────────────────────────────────────┐
│         Your Browser                    │
└────────────────┬────────────────────────┘
                 │ (HTTPS requests)
         ┌───────▼──────────┐
         │  Cloudflare DNS  │
         │  + Reverse Proxy │
         │  + CDN/Security  │
         └───────┬──────────┘
                 │
         ┌───────▼──────────────────┐
         │  FastAPI Backend Server  │
         │  (Serves embedded UI)    │
         │  + Database              │
         │  (Railway/Fly.io/VPS)    │
         └──────────────────────────┘
```

This is simpler because:
- ✅ No separate frontend deployment needed
- ✅ FastAPI serves both UI and API
- ✅ Cloudflare handles DNS, SSL, and caching

---

## Prerequisites
- Cloudflare account (free or paid)
- Git repository (GitHub, GitLab, or Bitbucket)
- Backend server URL (e.g., from Railway, Fly.io, or your own VPS)
- Node.js 18+ (for local builds)

---

## Step 1: Deploy Backend Server

### Option A: Railway (Recommended for simplicity)

1. Go to [Railway.app](https://railway.app)
2. Click **New Project** → **Deploy from GitHub**
3. Select your repository
4. Railway will detect it's a Python project
5. Configure environment variables:
   ```
   GROQ_API_KEY=your_key
   DATABASE_URL=your_postgres_url
   ```
6. Deploy

Your application will be at: `your-project.up.railway.app` (serves embedded UI + API)

### Option B: Fly.io

1. Install `flyctl`: `curl -L https://fly.io/install.sh | sh`
2. Run `fly launch` in your project root
3. Configure `fly.toml` (see template below)
4. Deploy with `fly deploy`

### Option C: Your Own VPS

1. Set up server with Ubuntu 22.04+
2. Install Python 3.11+, PostgreSQL
3. Clone repository and set up:
   ```bash
   cd /home/app/cybersec
   poetry install --no-dev
   export DATABASE_URL=postgresql://user:pass@localhost/cybersec
   gunicorn cybersec.api.main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker
   ```
4. Set up reverse proxy (Nginx) and SSL (Let's Encrypt)

---

## Step 2: Configure Cloudflare DNS & Reverse Proxy

### 2.1 DNS Configuration
In [Cloudflare Dashboard](https://dash.cloudflare.com):
1. Go to your domain → **DNS** → **Records**
2. Add a CNAME record:
   ```
   Type: CNAME
   Name: @ (or subdomain like app)
   Content: your-project.up.railway.app (your backend domain)
   Proxy status: Proxied (orange cloud)
   TTL: Auto
   ```

### 2.2 SSL/TLS Configuration
1. Go to **SSL/TLS** → **Overview**
2. Set to **Full** or **Full (strict)**
3. Cloudflare will automatically provision an SSL certificate

### 2.3 Create Firewall Rule (Optional Security)
1. Go to **Security** → **WAF**
2. Create rules to protect your application (rate limiting, DDoS protection)

---

## Step 3: Configure FastAPI for Production

### 3.1 Update CORS Settings
Update your FastAPI backend in `cybersec/api/main.py`:
```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://example.com",      # your domain
        "http://localhost:3000",     # development
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### 3.2 Enable Compression
Add this to `cybersec/api/main.py`:
```python
from fastapi.middleware.gzip import GZIPMiddleware

app.add_middleware(GZIPMiddleware, minimum_size=1000)
```

### 3.3 Database Configuration

For production, use a managed PostgreSQL service:
- **Railway**: Automatic PostgreSQL provisioning (easiest)
- **Fly.io**: Fly Postgres
- **Neon**: Serverless PostgreSQL
- **AWS RDS**: Full-featured managed database

Set the `DATABASE_URL` environment variable in your backend deployment.

---

## Environment Variables Checklist

### Backend (Railway/Fly.io/VPS)
- `GROQ_API_KEY` - Your Groq API key
- `DATABASE_URL` - PostgreSQL connection string (e.g., `postgresql://user:pass@host/dbname`)
- `SECRET_KEY` - JWT secret for authentication (generate with `openssl rand -hex 32`)
- `REDIS_URL` - Redis connection (if using Celery tasks)

---

## Monitoring & Debugging

### Cloudflare Analytics & Monitoring
- Go to **Analytics** tab to see traffic, cache hit rate
- **Real-time analytics** shows current requests
- **Page Rules** for caching optimization

### Backend Logs
- **Railway**: Click project → **Logs** tab
- **Fly.io**: `fly logs` command
- **VPS**: SSH in and check application logs

### Test Your Deployment
```bash
# Test application UI
curl https://example.com/

# Test API documentation
curl https://example.com/docs

# Test specific endpoint
curl https://example.com/health

# Test with redirect following
curl -L https://example.com
```

---

## Common Issues & Solutions

### Port Binding Issues
- Ensure backend listens on `0.0.0.0:8000`
- Check `Procfile` and `fly.toml` use correct port

### Database Connection Failed
- Verify `DATABASE_URL` environment variable is set correctly
- Check firewall rules allow database connections
- Run migrations: `alembic upgrade head`

### 502 Bad Gateway
- Check backend server logs
- Verify backend is running and responding
- Check Cloudflare proxy settings

### CORS Issues
- Update `CORSMiddleware` in FastAPI to allow Cloudflare domain
- Add `Vary: Origin` header for proper caching

### Slow Performance
- Enable Cloudflare caching for static assets
- Use Cloudflare Page Rules for optimization
- Check backend database performance
- Enable GZIP compression in FastAPI

---

## Cloudflare Cache Optimization

In **Caching** → **Cache Rules**:
```
URL contains: /static/
Cache TTL: 1 month
```

---

## Next Steps

1. ✅ Deploy backend to Railway/Fly.io/VPS
2. ✅ Set environment variables on backend
3. ✅ Run database migrations
4. ✅ Configure Cloudflare DNS
5. ✅ Set SSL/TLS to Full/Full Strict
6. ✅ Add DNS CNAME record pointing to backend
7. ✅ Test UI loads at your domain
8. ✅ Test API endpoints work
9. ✅ Configure Cloudflare caching rules (optional)

---

## Support

For issues:
- Cloudflare Docs: https://developers.cloudflare.com
- FastAPI Deployment: https://fastapi.tiangolo.com/deployment/
- Railway Docs: https://docs.railway.app
- Fly.io Docs: https://fly.io/docs/
