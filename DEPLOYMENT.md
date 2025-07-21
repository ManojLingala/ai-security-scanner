# AI Security Scanner - Deployment Guide

This document provides step-by-step instructions for deploying the AI Security Scanner in various environments.

## Quick Start (Docker - Recommended)

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/) installed
- [Docker Compose](https://docs.docker.com/compose/install/) installed
- Claude API key from [Anthropic Console](https://console.anthropic.com/)

### 1. Clone Repository
```bash
git clone <your-repository-url>
cd AISecurityScanner
```

### 2. Configure Environment
```bash
# Copy environment template
cp .env.example .env

# Edit .env file with your settings
nano .env
```

**Required environment variables:**
```bash
CLAUDE_API_KEY=your-claude-api-key-here
JWT_SECRET=YourProductionSecretKeyMustBeAtLeast256BitsLong!
```

### 3. Deploy
```bash
# Build and start services
docker-compose up --build -d

# Verify deployment
curl http://localhost:5105/api/health
```

### 4. Access Applications
- **API**: http://localhost:5105
- **Swagger UI**: http://localhost:5105/swagger/v1/swagger.json
- **RavenDB Studio**: http://localhost:8080
- **CLI**: Available inside container at `/usr/local/bin/aiscan`

## CLI Usage (After Docker Deployment)

### Access CLI in Container
```bash
# Execute CLI commands in running container
docker-compose exec aisecurityscanner aiscan --help

# Or access container shell
docker-compose exec aisecurityscanner bash
aiscan version
```

### Install CLI Locally
```bash
# Build CLI locally
cd src/AISecurityScanner.CLI
dotnet build --configuration Release

# Create global tool package
dotnet pack --configuration Release

# Install as global tool
dotnet tool install --global --add-source ./bin/Release AISecurityScanner.CLI

# Test installation
aiscan --help
```

## Manual Installation (Without Docker)

### Prerequisites
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- [RavenDB](https://ravendb.net/download) Community Edition
- [Claude Code CLI](https://claude.ai/code) (for CLI authentication)

### 1. Setup RavenDB
```bash
# Download and start RavenDB
wget https://hibernatingrhinos.com/downloads/ravendb-5.4.6-linux-x64.tar.bz2
tar -xvf ravendb-5.4.6-linux-x64.tar.bz2
cd RavenDB
./run.sh

# Access RavenDB Studio: http://localhost:8080
# Create database: AISecurityScanner-Dev
```

### 2. Configure Application
```bash
# Navigate to API project
cd src/AISecurityScanner.API

# Copy configuration template
cp appsettings.json appsettings.Development.json

# Edit configuration
nano appsettings.Development.json
```

**Update configuration:**
```json
{
  "RavenDb": {
    "Urls": ["http://localhost:8080"],
    "Database": "AISecurityScanner-Dev"
  },
  "AIProviders": {
    "Claude": {
      "ApiKey": "your-claude-api-key-here"
    }
  },
  "Jwt": {
    "Secret": "YourSecretKeyHereMustBeAtLeast256Bits12345!@#$%"
  }
}
```

### 3. Build and Run
```bash
# Restore and build
dotnet restore
dotnet build

# Run API
dotnet run

# In separate terminal - run CLI
cd ../AISecurityScanner.CLI
dotnet run -- --help
```

## Production Deployment

### Using Kubernetes

#### 1. Create Namespace
```bash
kubectl create namespace aisecurityscanner
```

#### 2. Create Secrets
```bash
# Create JWT secret
kubectl create secret generic jwt-secret \
  --from-literal=secret='YourProductionSecretKeyMustBeAtLeast256BitsLong!' \
  -n aisecurityscanner

# Create Claude API key secret
kubectl create secret generic claude-secret \
  --from-literal=api-key='your-claude-api-key-here' \
  -n aisecurityscanner
```

#### 3. Deploy RavenDB
```yaml
# ravendb-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ravendb
  namespace: aisecurityscanner
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ravendb
  template:
    metadata:
      labels:
        app: ravendb
    spec:
      containers:
      - name: ravendb
        image: ravendb/ravendb:5.4-ubuntu-latest
        ports:
        - containerPort: 8080
        env:
        - name: RAVEN_Setup_Mode
          value: "None"
        - name: RAVEN_Security_UnsecuredAccessAllowed
          value: "PublicNetwork"
        - name: RAVEN_License_Eula_Accepted
          value: "true"
        volumeMounts:
        - name: ravendb-storage
          mountPath: /opt/RavenDB/Server/RavenData
      volumes:
      - name: ravendb-storage
        persistentVolumeClaim:
          claimName: ravendb-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: ravendb-service
  namespace: aisecurityscanner
spec:
  selector:
    app: ravendb
  ports:
  - port: 8080
    targetPort: 8080
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ravendb-pvc
  namespace: aisecurityscanner
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

#### 4. Deploy Application
```yaml
# app-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aisecurityscanner
  namespace: aisecurityscanner
spec:
  replicas: 3
  selector:
    matchLabels:
      app: aisecurityscanner
  template:
    metadata:
      labels:
        app: aisecurityscanner
    spec:
      containers:
      - name: aisecurityscanner
        image: your-registry/aisecurityscanner:latest
        ports:
        - containerPort: 5105
        env:
        - name: ASPNETCORE_ENVIRONMENT
          value: "Production"
        - name: RavenDb__Urls__0
          value: "http://ravendb-service:8080"
        - name: RavenDb__Database
          value: "AISecurityScanner-Prod"
        - name: Jwt__Secret
          valueFrom:
            secretKeyRef:
              name: jwt-secret
              key: secret
        - name: AIProviders__Claude__ApiKey
          valueFrom:
            secretKeyRef:
              name: claude-secret
              key: api-key
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /api/health
            port: 5105
          initialDelaySeconds: 60
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /api/health
            port: 5105
          initialDelaySeconds: 30
          periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: aisecurityscanner-service
  namespace: aisecurityscanner
spec:
  selector:
    app: aisecurityscanner
  ports:
  - port: 80
    targetPort: 5105
  type: LoadBalancer
```

#### 5. Apply Manifests
```bash
kubectl apply -f ravendb-deployment.yaml
kubectl apply -f app-deployment.yaml

# Check deployment
kubectl get pods -n aisecurityscanner
kubectl get services -n aisecurityscanner
```

### Using Azure Container Instances

#### 1. Create Resource Group
```bash
az group create --name aisecurityscanner-rg --location eastus
```

#### 2. Deploy RavenDB
```bash
az container create \
  --resource-group aisecurityscanner-rg \
  --name ravendb \
  --image ravendb/ravendb:5.4-ubuntu-latest \
  --ports 8080 \
  --environment-variables \
    RAVEN_Setup_Mode=None \
    RAVEN_Security_UnsecuredAccessAllowed=PublicNetwork \
    RAVEN_License_Eula_Accepted=true \
  --dns-name-label ravendb-aiscan \
  --cpu 1 \
  --memory 2
```

#### 3. Deploy Application
```bash
az container create \
  --resource-group aisecurityscanner-rg \
  --name aisecurityscanner \
  --image your-registry/aisecurityscanner:latest \
  --ports 5105 \
  --environment-variables \
    ASPNETCORE_ENVIRONMENT=Production \
    RavenDb__Urls__0=http://ravendb-aiscan.eastus.azurecontainer.io:8080 \
    RavenDb__Database=AISecurityScanner-Prod \
  --secure-environment-variables \
    Jwt__Secret='YourProductionSecretKeyMustBeAtLeast256BitsLong!' \
    AIProviders__Claude__ApiKey='your-claude-api-key-here' \
  --dns-name-label aiscan-api \
  --cpu 1 \
  --memory 1
```

## CI/CD Pipeline Examples

### GitHub Actions
```yaml
# .github/workflows/deploy.yml
name: Deploy to Production

on:
  push:
    branches: [main]

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Setup Docker Buildx
      uses: docker/setup-buildx-action@v3
      
    - name: Login to Registry
      uses: docker/login-action@v3
      with:
        registry: your-registry.azurecr.io
        username: ${{ secrets.REGISTRY_USERNAME }}
        password: ${{ secrets.REGISTRY_PASSWORD }}
        
    - name: Build and Push
      uses: docker/build-push-action@v5
      with:
        context: .
        push: true
        tags: your-registry.azurecr.io/aisecurityscanner:${{ github.sha }}
        
    - name: Deploy to Azure
      run: |
        az container create \
          --resource-group ${{ secrets.RESOURCE_GROUP }} \
          --name aisecurityscanner \
          --image your-registry.azurecr.io/aisecurityscanner:${{ github.sha }} \
          --environment-variables \
            ASPNETCORE_ENVIRONMENT=Production \
          --secure-environment-variables \
            AIProviders__Claude__ApiKey='${{ secrets.CLAUDE_API_KEY }}'
```

## Monitoring and Maintenance

### Health Monitoring
```bash
# Check application health
curl http://your-domain:5105/api/health

# Check detailed health status
curl http://your-domain:5105/api/health/detailed
```

### Log Management
```bash
# Docker logs
docker-compose logs -f aisecurityscanner

# Kubernetes logs
kubectl logs -f deployment/aisecurityscanner -n aisecurityscanner

# Export logs
docker-compose logs aisecurityscanner > app-logs.txt
```

### Backup and Recovery
```bash
# Backup RavenDB data
docker-compose exec ravendb /opt/RavenDB/Server/rvn admin-channel /opt/RavenDB/Server/RavenData backup /backup

# Restore from backup
docker-compose exec ravendb /opt/RavenDB/Server/rvn admin-channel /opt/RavenDB/Server/RavenData restore /backup
```

### Performance Tuning
```yaml
# docker-compose.override.yml
version: '3.8'
services:
  aisecurityscanner:
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '1.0'
        reservations:
          memory: 512M
          cpus: '0.5'
    environment:
      - DOTNET_GCServer=1
      - DOTNET_gcConcurrent=1
```

## Troubleshooting

### Common Issues

#### RavenDB Connection Issues
```bash
# Check RavenDB status
curl http://localhost:8080/debug/info

# Check network connectivity
docker-compose exec aisecurityscanner ping ravendb
```

#### Memory Issues
```bash
# Monitor memory usage
docker stats aisecurityscanner

# Increase memory limits
# Edit docker-compose.yml:
services:
  aisecurityscanner:
    deploy:
      resources:
        limits:
          memory: 2G
```

#### Authentication Issues
```bash
# Verify environment variables
docker-compose exec aisecurityscanner env | grep CLAUDE

# Test CLI authentication
docker-compose exec aisecurityscanner aiscan auth status
```

### Support
For issues or questions:
1. Check application logs
2. Verify environment configuration
3. Test health endpoints
4. Review this deployment guide
5. Create an issue in the repository

## Security Considerations

### Production Checklist
- [ ] Use strong JWT secrets (256-bit minimum)
- [ ] Enable HTTPS with valid certificates
- [ ] Secure RavenDB with authentication
- [ ] Use secrets management for API keys
- [ ] Enable audit logging
- [ ] Configure CORS for known origins
- [ ] Set up monitoring and alerting
- [ ] Implement backup strategy
- [ ] Use private networks/VPCs
- [ ] Enable container image scanning