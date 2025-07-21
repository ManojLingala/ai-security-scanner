# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy project files and restore dependencies
COPY ["src/AISecurityScanner.Domain/AISecurityScanner.Domain.csproj", "src/AISecurityScanner.Domain/"]
COPY ["src/AISecurityScanner.Application/AISecurityScanner.Application.csproj", "src/AISecurityScanner.Application/"]
COPY ["src/AISecurityScanner.Infrastructure/AISecurityScanner.Infrastructure.csproj", "src/AISecurityScanner.Infrastructure/"]
COPY ["src/AISecurityScanner.API/AISecurityScanner.API.csproj", "src/AISecurityScanner.API/"]
COPY ["src/AISecurityScanner.CLI/AISecurityScanner.CLI.csproj", "src/AISecurityScanner.CLI/"]

# Restore dependencies
RUN dotnet restore "src/AISecurityScanner.API/AISecurityScanner.API.csproj"
RUN dotnet restore "src/AISecurityScanner.CLI/AISecurityScanner.CLI.csproj"

# Copy source code
COPY . .

# Build API
WORKDIR "/src/src/AISecurityScanner.API"
RUN dotnet build "AISecurityScanner.API.csproj" -c Release -o /app/build

# Publish API
RUN dotnet publish "AISecurityScanner.API.csproj" -c Release -o /app/publish /p:UseAppHost=false

# Build CLI
WORKDIR "/src/src/AISecurityScanner.CLI"
RUN dotnet build "AISecurityScanner.CLI.csproj" -c Release -o /app/cli-build
RUN dotnet publish "AISecurityScanner.CLI.csproj" -c Release -o /app/cli-publish /p:UseAppHost=false

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app

# Install curl for health checks
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Copy published applications
COPY --from=build /app/publish .
COPY --from=build /app/cli-publish ./cli

# Create directories for volumes
RUN mkdir -p /app/scans /app/logs

# Set permissions
RUN chmod +x /app/cli/aiscan

# Create symbolic link for CLI access
RUN ln -sf /app/cli/aiscan /usr/local/bin/aiscan

# Expose port
EXPOSE 5105

# Set environment
ENV ASPNETCORE_ENVIRONMENT=Production
ENV ASPNETCORE_URLS=http://+:5105

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:5105/api/health || exit 1

# Run API by default
ENTRYPOINT ["dotnet", "AISecurityScanner.API.dll"]