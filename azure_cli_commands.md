# Azure CLI Commands for Region Policy Check

## Install Azure CLI (Alternative Methods)

### Method 1: Using pip (Recommended for your system)
```bash
pip install azure-cli
```

### Method 2: Using Docker
```bash
docker run -it --rm mcr.microsoft.com/azure-cli:latest
```

### Method 3: Manual download
```bash
curl -L https://aka.ms/InstallAzureCLIDeb -o azure-cli.deb
sudo dpkg -i azure-cli.deb
sudo apt-get install -f  # Fix dependencies
```

## Login to Azure
```bash
az login
# This will open a browser for authentication
```

## Check Region Policies

### 1. List all policy assignments
```bash
az policy assignment list --output table
```

### 2. Check for region restrictions
```bash
az policy assignment list --query "[?contains(policyDefinitionId, 'region')]" --output table
```

### 3. Get detailed policy information
```bash
az policy assignment list --query "[?contains(policyDefinitionId, 'region')]" --output json
```

### 4. Check allowed locations for your subscription
```bash
az account list-locations --query "[?metadata.regionCategory=='Recommended' || metadata.regionCategory=='Other'].{Name:name, DisplayName:displayName, Category:metadata.regionCategory}" --output table
```

### 5. Check your subscription's resource providers
```bash
az provider list --query "[].{Provider:namespace, RegistrationState:registrationState}" --output table
```

## Alternative: Check in Azure Portal

If CLI doesn't work, check in Azure Portal:
1. Go to **Subscriptions** → Select your subscription
2. **Resource providers** → Look for allowed locations
3. **Policies** → Check for region restriction policies

## Common Allowed Regions to Try

Based on typical Azure policies:
- **East US** (eastus)
- **West Europe** (westeurope)
- **Southeast Asia** (southeastasia)
- **Australia East** (australiaeast)
- **Central US** (centralus)
- **North Europe** (northeurope)
- **UK South** (uksouth)
- **Canada Central** (canadacentral)

## If All Regions Fail

Contact Azure Support:
1. Azure Portal → **Help + Support** → **New support request**
2. **Issue type**: Technical
3. **Service**: All services → **Subscription Management**
4. **Problem type**: Subscription properties and limits
5. **Subject**: Request access to additional regions