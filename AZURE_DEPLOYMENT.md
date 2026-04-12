# Azure Deployment Guide

## Overview
This guide covers deploying the CyberSec application on Azure. Your FastAPI backend serves the embedded UI, and Azure handles hosting, scaling, and SSL.

## Architecture
```
┌─────────────────────────────────────────┐
│         Azure CDN / Front Door          │
│  (Optional - Global distribution)       │
└────────────────┬────────────────────────┘
                 │ (HTTPS requests)
         ┌───────▼──────────┐
         │  Azure App Service│
         │  (FastAPI + UI)   │
         │  + Database       │
         └───────────────────┘
```

## Prerequisites
- Azure account (free tier available)
- Git repository (GitHub, Azure DevOps, or Bitbucket)
- Azure CLI installed (optional, for CLI deployment)

---

## Step 1: Deploy Backend to Azure App Service

### Option A: Azure Portal (Recommended for beginners)

1. Go to [Azure Portal](https://portal.azure.com)
2. Click **Create a resource** → **Web App**
3. Configure:
   - **Subscription**: Your subscription
   - **Resource Group**: Create new or use existing
   - **Name**: `cybersec-app` (must be globally unique)
   - **Publish**: Code
   - **Runtime stack**: Python 3.11
   - **Operating System**: Linux
   - **Region**: Choose from **ALLOWED REGIONS** below ⬇️
   - **App Service Plan**: Create new (B1 Basic, $13.14/mo)

4. Click **Review + create** → **Create**

### 🔓 Allowed Regions for Your Subscription

Your Azure subscription has region restrictions. Based on your policy, you can **ONLY** deploy to these regions:

**✅ ALLOWED REGIONS:**
- **East Asia** (eastasia)
- **Southeast Asia** (southeastasia) ⭐ - **Try this first**
- **UAE North** (uaenorth)
- **Austria East** (austriaeast)
- **Malaysia West** (malaysiawest)

**❌ NOT ALLOWED:** East US, West Europe, Australia East, etc.

### 🚨 Region Policy Error Solution:

If you get: *"Resource was disallowed by Azure policy"*

**Option 1: Change Region**
- Go back and select a different region from the **ALLOWED REGIONS** above
- Try **Southeast Asia** first (closest to you)

**Option 2: Contact Support**
- Contact Azure Support to request additional regions
- This usually takes 24-48 hours
- Request access to additional regions for your subscription
- This usually takes 24-48 hours

**Option 3: Check Allowed Regions**
- In Azure Portal → **Subscriptions**
- Select your subscription
- **Resource providers** → Check allowed locations

### After App Service Creation - Connect GitHub:

1. **Go to your App Service** (search for "cybersec-app" in portal)
2. **Click "Deployment Center"** in the left menu
3. **Choose "GitHub"** as source
4. **Authorize Azure** to access your GitHub account
5. **Select your repository** and branch (main)
6. **Save** - this enables automatic deployment

### After App Service Creation - Add Environment Variables:

1. **Go to your App Service**
2. **Click "Configuration"** in the left menu
3. **Click "Application settings"** tab
4. **Click "New application setting"** for each variable:
   ```
   Name: GROQ_API_KEY, Value: your_groq_key
   Name: DATABASE_URL, Value: postgresql://user:pass@host/dbname
   Name: REDIS_URL, Value: redis://host:port
   Name: APP_DEBUG, Value: false
   Name: CORS_ORIGINS, Value: https://cybersec-app.azurewebsites.net
   ```
5. **Save** each setting

### After App Service Creation - Configure Startup:

1. **Go to your App Service**
2. **Click "Configuration"** in the left menu
3. **Click "General settings"** tab
4. **Startup Command**: `gunicorn cybersec.api.main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT`
5. **Save**

### Option B: Azure CLI

```bash
# Install Azure CLI if not installed
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Login
az login

# Create resource group
az group create --name cybersec-rg --location eastus

# Create App Service plan
az appservice plan create --name cybersec-plan --resource-group cybersec-rg --sku B1 --is-linux

# Create web app
az webapp create --resource-group cybersec-rg --plan cybersec-plan --name cybersec-app --runtime "PYTHON:3.11"

# Configure deployment from GitHub
az webapp deployment source config --name cybersec-app --resource-group cybersec-rg --repo-url https://github.com/YOUR_USERNAME/YOUR_REPO --branch main --manual-integration
```

---

## Step 2: Configure Environment Variables

### Via Azure Portal:
1. Go to your App Service → **Configuration**
2. Add application settings:
   ```
   Name: GROQ_API_KEY, Value: your_groq_key
   Name: DATABASE_URL, Value: postgresql://user:pass@host/dbname
   Name: REDIS_URL, Value: redis://host:port
   Name: APP_DEBUG, Value: false
   Name: CORS_ORIGINS, Value: https://cybersec-app.azurewebsites.net
   ```

### Via Azure CLI:
```bash
az webapp config appsettings set --name cybersec-app --resource-group cybersec-rg --setting GROQ_API_KEY=your_key
az webapp config appsettings set --name cybersec-app --resource-group cybersec-rg --setting DATABASE_URL=postgresql://...
```

---

## Step 3: Set Up Database

### Option A: Azure Database for PostgreSQL (Recommended)

1. **Back in Azure Portal main page**, click **Create a resource**
2. Search for **"Azure Database for PostgreSQL"**
3. Click **Create** → **Single server**
4. Configure:
   - **Resource Group**: Use the **SAME** as your App Service
   - **Server name**: cybersec-db (unique)
   - **Location**: **SAME REGION as your App Service** (East US, etc.)
   - **Version**: 16
   - **Compute + storage**: Basic, 1 vCore, 32GB
   - **Admin username**: postgres
   - **Password**: Strong password (save this!)

5. Click **Review + create** → **Create**
6. **After creation**, go to your PostgreSQL server
7. **Click "Connection strings"** in left menu
8. **Copy the connection string** and replace with your password
9. **Go back to your App Service** → **Configuration** → **Application settings**
10. **Add DATABASE_URL** with the connection string

### Option B: Use Railway/External Database

You can use Railway for PostgreSQL and connect to it from Azure - just add the Railway connection string to your App Service environment variables.

---

## Step 4: Configure Startup Command

In Azure App Service → **Configuration** → **General settings**:
- **Startup Command**: `gunicorn cybersec.api.main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT`

Or via CLI:
```bash
az webapp config set --name cybersec-app --resource-group cybersec-rg --startup-file "gunicorn cybersec.api.main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT"
```

---

## Step 5: Deploy and Test

### After Setting Up Everything:

1. **Push your code to GitHub** (if using Deployment Center)
2. **Azure will automatically deploy** your app
3. **Monitor deployment** in **Deployment Center** → **Logs**

### Manual Deployment (if needed):
```bash
# Via Azure CLI
az webapp deployment source sync --name cybersec-app --resource-group cybersec-rg
```

### Test Your Deployment:
```bash
# Test UI
curl https://cybersec-app.azurewebsites.net/

# Test API docs
curl https://cybersec-app.azurewebsites.net/docs

# Test health endpoint
curl https://cybersec-app.azurewebsites.net/health
```

### Check Logs:
1. **Go to your App Service**
2. **Click "Log stream"** in left menu
3. **See real-time logs**

---

## Step 6: Configure Custom Domain (Optional)

1. Go to App Service → **Custom domains**
2. Add your domain
3. Update DNS records at your registrar
4. Azure will provision SSL certificate automatically

---

## Step 7: Enable Azure CDN (Optional - for global distribution)

1. Create Azure CDN profile
2. Add endpoint pointing to your App Service
3. Update DNS to point to CDN endpoint

---

## Environment Variables Checklist

### Azure App Service Settings:
- `GROQ_API_KEY` - Your Groq API key
- `DATABASE_URL` - PostgreSQL connection string
- `REDIS_URL` - Redis connection (if using)
- `APP_DEBUG` - false for production
- `CORS_ORIGINS` - Your Azure domain
- `SECRET_KEY` - Random string for JWT

---

## Monitoring & Debugging

### Azure Portal:
- **App Service** → **Logs** → Enable Application Logging
- **Metrics** → Monitor CPU, Memory, Requests
- **Log stream** → Real-time logs

### Azure CLI:
```bash
# View logs
az webapp log tail --name cybersec-app --resource-group cybersec-rg

# Download logs
az webapp log download --name cybersec-app --resource-group cybersec-rg --log-file logs.zip
```

---

## Scaling

### Vertical Scaling:
- Go to App Service → **Scale up** → Choose higher tier (S1, P1V2, etc.)

### Horizontal Scaling:
- Enable **Scale out** → Set instance count
- Configure **Auto scaling** based on CPU/memory

---

## Common Issues & Solutions

### Port Issues:
- Azure assigns random port via `$PORT` environment variable
- Use `--bind 0.0.0.0:$PORT` in startup command

### Database Connection:
- Ensure firewall allows Azure services
- Use Azure Database for PostgreSQL for seamless integration

### Memory Issues:
- Upgrade to higher App Service plan
- Optimize Python app (use gunicorn workers)

### Deployment Failures:
- Check deployment logs in Azure Portal
- Ensure all dependencies in `requirements.txt`
- Verify Python version compatibility

---

## Cost Estimation

| Service | Tier | Monthly Cost |
|---------|------|--------------|
| App Service | B1 | $13.14 |
| PostgreSQL | Basic (1 vCore) | $25.00 |
| CDN | Standard | $0.10/GB |
| **Total** | | **~$40/mo** |

---

## Next Steps

1. ✅ Create Azure App Service
2. ✅ Set environment variables
3. ✅ Configure database
4. ✅ Deploy code
5. ✅ Test application
6. ✅ Set up custom domain (optional)
7. ✅ Configure monitoring

---

## Support

For issues:
- Azure Docs: https://docs.microsoft.com/en-us/azure/app-service/
- FastAPI Deployment: https://fastapi.tiangolo.com/deployment/
- Azure CLI: https://docs.microsoft.com/en-us/cli/azure/