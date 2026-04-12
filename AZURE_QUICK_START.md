# Azure Deployment Quick Reference

## 🚨 REGION POLICY ISSUE DETECTED

## Current Status: App Service Creation Blocked by Region Policy

## 🔓 SOLUTION: Choose Allowed Region

### When creating App Service, select from these regions ONLY:
- **East Asia** (eastasia)
- **Southeast Asia** (southeastasia) ⭐ - **Try this first**
- **UAE North** (uaenorth)
- **Austria East** (austriaeast)
- **Malaysia West** (malaysiawest)

### These regions are NOT allowed:
- ❌ East US, West Europe, Australia East, etc.

### If you need other regions:
1. **Contact Azure Support** to request additional regions
2. **Check your subscription** → **Resource providers** for allowed locations
3. **Use a different subscription** if available

## Next Steps (after selecting allowed region):

### 1. Connect GitHub
- **In Azure Portal** → Search for your App Service
- **Left menu** → **Deployment Center**
- **Source**: GitHub
- **Authorize** Azure to access GitHub
- **Select repository** and **main branch**
- **Save**

### 2. Add Environment Variables
- **In your App Service** → **Configuration**
- **Application settings** tab
- **Add new settings**:
  ```
  GROQ_API_KEY = your_actual_groq_key
  DATABASE_URL = postgresql://user:pass@host/db (will add after DB creation)
  APP_DEBUG = false
  CORS_ORIGINS = https://your-app-name.azurewebsites.net
  ```

### 3. Configure Startup Command
- **In Configuration** → **General settings** tab
- **Startup Command**: `gunicorn cybersec.api.main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT`
- **Save**

### 4. Create Database in SAME Region
- **Azure Portal main** → **Create a resource**
- Search: **Azure Database for PostgreSQL**
- **Single server** → Create
- **SAME resource group** as your App Service
- **SAME region** as your App Service ⭐ (critical!)
- **Basic tier** (cheapest)
- **Save the password!**

### 5. Connect Database
- **Go to PostgreSQL server** → **Connection strings**
- **Copy connection string** → Replace password
- **Back to App Service** → **Configuration** → **Add DATABASE_URL**

### 6. Deploy
- **Push code to GitHub** → Auto-deploy
- **Check logs** in **Log stream**

### 7. Test
```bash
curl https://your-app-name.azurewebsites.net/
```

## Common Issues:
- **Can't find Deployment Center?** Make sure you're in the App Service, not the resource group
- **GitHub not connecting?** Check repository permissions
- **App not starting?** Check **Log stream** for errors
- **Database connection failed?** Verify firewall allows Azure services

## Need Help?
- Check [AZURE_DEPLOYMENT.md](AZURE_DEPLOYMENT.md) for detailed guide
- Azure docs: https://docs.microsoft.com/en-us/azure/app-service/