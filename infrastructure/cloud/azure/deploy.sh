#!/bin/bash
# Azure Deployment Script

echo "🚀 Starting Azure deployment..."

# Check if Azure CLI is installed
if ! command -v az &> /dev/null; then
    echo "Installing Azure CLI..."
    curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
fi

# Login to Azure
echo "Please login to Azure:"
az login

# Set variables
RESOURCE_GROUP="cybersec-rg"
APP_NAME="cybersec-app-$(date +%s)"  # Make unique
LOCATION="eastus"
PLAN_NAME="cybersec-plan"

echo "Using resource group: $RESOURCE_GROUP"
echo "Using app name: $APP_NAME"

# Create resource group
echo "Creating resource group..."
az group create --name $RESOURCE_GROUP --location $LOCATION

# Create App Service plan
echo "Creating App Service plan..."
az appservice plan create --name $PLAN_NAME --resource-group $RESOURCE_GROUP --sku B1 --is-linux

# Create web app
echo "Creating web app..."
az webapp create --resource-group $RESOURCE_GROUP --plan $PLAN_NAME --name $APP_NAME --runtime "PYTHON:3.11"

# Configure deployment from GitHub
read -p "Enter your GitHub repository URL: " REPO_URL
read -p "Enter your GitHub branch (default: main): " BRANCH
BRANCH=${BRANCH:-main}

az webapp deployment source config --name $APP_NAME --resource-group $RESOURCE_GROUP --repo-url $REPO_URL --branch $BRANCH --manual-integration

# Set environment variables
echo "Setting environment variables..."
read -p "Enter your GROQ API key: " GROQ_KEY
read -p "Enter your database URL (leave empty to use Railway): " DB_URL

az webapp config appsettings set --name $APP_NAME --resource-group $RESOURCE_GROUP --setting GROQ_API_KEY=$GROQ_KEY
az webapp config appsettings set --name $APP_NAME --resource-group $RESOURCE_GROUP --setting APP_DEBUG=false
az webapp config appsettings set --name $APP_NAME --resource-group $RESOURCE_GROUP --setting CORS_ORIGINS=https://$APP_NAME.azurewebsites.net

if [ ! -z "$DB_URL" ]; then
    az webapp config appsettings set --name $APP_NAME --resource-group $RESOURCE_GROUP --setting DATABASE_URL=$DB_URL
fi

# Set startup command
az webapp config set --name $APP_NAME --resource-group $RESOURCE_GROUP --startup-file "gunicorn cybersec.apps.api.main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:\$PORT"

echo "✅ Deployment complete!"
echo "Your app will be available at: https://$APP_NAME.azurewebsites.net"
echo ""
echo "Next steps:"
echo "1. Push your code to GitHub to trigger deployment"
echo "2. Check deployment logs: az webapp log tail --name $APP_NAME --resource-group $RESOURCE_GROUP"
echo "3. Test your app: curl https://$APP_NAME.azurewebsites.net/"
