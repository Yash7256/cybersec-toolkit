# Azure Deployment - Post-Deployment Checklist

## ✅ COMPLETED: App Service Created in Southeast Asia

## 🎯 NEXT STEPS (in order):

### 1. Connect GitHub Repository
**Location:** App Service → **Deployment Center**
- **Source:** GitHub
- **Authorize** Azure to access GitHub
- **Select:** Your `cybersec` repository
- **Branch:** `main`
- **Save**

### 2. Add Environment Variables
**Location:** App Service → **Configuration** → **Application settings**
Add these variables:
```
Name: GROQ_API_KEY, Value: your_actual_groq_api_key
Name: APP_DEBUG, Value: false
Name: CORS_ORIGINS, Value: https://your-app-name.azurewebsites.net
Name: DATABASE_URL, Value: [will add after DB creation]
```

### 3. Configure Startup Command
**Location:** Configuration → **General settings**
```
Startup Command: gunicorn cybersec.api.main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT
```

### 4. Create PostgreSQL Database
**Location:** Azure Portal → **Create a resource**
- Search: **Azure Database for PostgreSQL**
- **Single server** → Create
- **Resource Group:** Same as App Service
- **Server name:** `cybersec-db-[random]` (unique)
- **Location:** `Southeast Asia` (SAME as App Service)
- **Version:** 16
- **Compute:** Basic, 1 vCore, 32GB
- **Admin:** postgres / [strong password]
- **Create**

### 5. Connect Database to App Service
**After DB creation:**
- Go to PostgreSQL → **Connection strings**
- Copy the connection string
- Replace password in the string
- Add to App Service **Configuration** as `DATABASE_URL`

### 6. Deploy & Test
- **Push code** to GitHub → Auto-deploy
- **Check logs:** App Service → **Log stream**
- **Test URLs:**
  - UI: `https://your-app-name.azurewebsites.net/`
  - API: `https://your-app-name.azurewebsites.net/docs`

### 7. Database Migration (if needed)
```bash
# If you need to run migrations:
az webapp ssh --resource-group your-rg --name your-app-name
cd /home/site/wwwroot
alembic upgrade head
```

## 🔍 TROUBLESHOOTING:

### If deployment fails:
- Check **Deployment Center** → **Logs**
- Verify all environment variables are set
- Check **Log stream** for Python errors

### If app doesn't start:
- Verify `DATABASE_URL` is correct
- Check `GROQ_API_KEY` is valid
- Ensure startup command is correct

### If database connection fails:
- Verify PostgreSQL firewall allows Azure services
- Check connection string format
- Ensure same region (Southeast Asia)

## 📊 MONITORING:
- **Metrics:** App Service → **Metrics**
- **Logs:** App Service → **Log stream**
- **Database:** PostgreSQL → **Metrics**

## 🚀 FINAL STEP:
Once everything works, your CyberSec app will be live at:
`https://your-app-name.azurewebsites.net/`

## 💡 PRO TIPS:
- Enable **Application Insights** for advanced monitoring
- Set up **auto-scaling** if needed
- Configure **backup** for PostgreSQL
- Add **custom domain** when ready