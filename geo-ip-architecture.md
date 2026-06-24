# Geo IP Architecture and User Flow

## System Architecture

```mermaid
graph TB
    subgraph "Client Layer"
        User[User/Client Application]
        WebApp[Web Application]
        MobileApp[Mobile App]
        API[API Client]
    end

    subgraph "Load Balancer Layer"
        LB[Load Balancer<br/>Nginx/HAProxy]
    end

    subgraph "API Gateway Layer"
        Gateway[API Gateway<br/>Kong/AWS API Gateway]
        RateLimiter[Rate Limiter]
        Auth[Authentication<br/>JWT/OAuth2]
    end

    subgraph "Application Layer"
        API1[Geo IP API Service 1]
        API2[Geo IP API Service 2]
        API3[Geo IP API Service 3]
    end

    subgraph "Cache Layer"
        Redis[(Redis Cache<br/>Hot Data)]
        Memcached[(Memcached<br/>Session Data)]
    end

    subgraph "Database Layer"
        PostgreSQL[(PostgreSQL<br/>User Data)]
        MongoDB[(MongoDB<br/>IP Database)]
        MaxMind[(MaxMind DB<br/>GeoIP2)]
    end

    subgraph "External Services"
        MaxMindAPI[MaxMind GeoIP2 API]
        IPInfo[IPInfo.io API]
        IPStack[IPStack API]
    end

    subgraph "Message Queue"
        Kafka[Kafka Message Queue]
        RabbitMQ[RabbitMQ]
    end

    subgraph "Analytics & Monitoring"
        Prometheus[Prometheus<br/>Metrics]
        Grafana[Grafana<br/>Dashboards]
        ELK[ELK Stack<br/>Logs]
    end

    User -->|HTTP/HTTPS| WebApp
    User -->|HTTP/HTTPS| MobileApp
    User -->|REST/GraphQL| API
    WebApp --> LB
    MobileApp --> LB
    API --> LB
    LB --> Gateway
    Gateway --> RateLimiter
    RateLimiter --> Auth
    Auth --> API1
    Auth --> API2
    Auth --> API3
    API1 --> Redis
    API2 --> Redis
    API3 --> Redis
    API1 --> Memcached
    API2 --> Memcached
    API3 --> Memcached
    Redis -->|Cache Miss| PostgreSQL
    Redis -->|Cache Miss| MongoDB
    Redis -->|Cache Miss| MaxMind
    API1 --> MaxMindAPI
    API2 --> IPInfo
    API3 --> IPStack
    API1 --> Kafka
    API2 --> Kafka
    API3 --> RabbitMQ
    Kafka --> Analytics
    RabbitMQ --> Analytics
    API1 --> Prometheus
    API2 --> Prometheus
    API3 --> Prometheus
    Prometheus --> Grafana
    API1 --> ELK
    API2 --> ELK
    API3 --> ELK
```

## User Flow Diagram

```mermaid
sequenceDiagram
    participant User as User/Client
    participant LB as Load Balancer
    participant Gateway as API Gateway
    participant API as Geo IP Service
    participant Cache as Redis Cache
    participant DB as Database
    participant External as External GeoIP API

    User->>LB: 1. Request IP Geolocation
    LB->>Gateway: 2. Forward Request
    Gateway->>Gateway: 3. Rate Limit Check
    Gateway->>Gateway: 4. Authentication
    Gateway->>API: 5. Authenticated Request
    
    API->>Cache: 6. Check Cache for IP
    alt Cache Hit
        Cache-->>API: 7. Return Cached Data
        API-->>Gateway: 8. Return Geo Data
    else Cache Miss
        API->>DB: 9. Query Local Database
        alt DB Hit
            DB-->>API: 10. Return Geo Data
            API->>Cache: 11. Update Cache
            API-->>Gateway: 12. Return Geo Data
        else DB Miss
            API->>External: 13. Query External API
            External-->>API: 14. Return Geo Data
            API->>DB: 15. Store in Database
            API->>Cache: 16. Update Cache
            API-->>Gateway: 17. Return Geo Data
        end
    end
    
    Gateway-->>LB: 18. Response
    LB-->>User: 19. Geolocation Data
```

## Detailed Component Architecture

```mermaid
graph LR
    subgraph "Geo IP Service Components"
        Controller[REST Controller]
        Service[Business Logic Layer]
        Repository[Data Access Layer]
        Validator[Input Validator]
        Formatter[Response Formatter]
    end

    subgraph "Data Processing"
        Parser[IP Parser]
        GeoCoder[GeoCoder]
        Enricher[Data Enricher]
        Sanitizer[Data Sanitizer]
    end

    subgraph "Security"
        IPWhitelist[IP Whitelist]
        DDoSProtection[DDoS Protection]
        InputSanitization[Input Sanitization]
        Encryption[Data Encryption]
    end

    Controller --> Validator
    Validator --> Service
    Service --> Repository
    Service --> Parser
    Parser --> GeoCoder
    GeoCoder --> Enricher
    Enricher --> Sanitizer
    Sanitizer --> Formatter
    Formatter --> Controller
    
    Controller --> IPWhitelist
    Service --> DDoSProtection
    Validator --> InputSanitization
    Repository --> Encryption
```

## Data Flow Architecture

```mermaid
graph TD
    subgraph "Ingestion Pipeline"
        Source[IP Address Source]
        Collector[Data Collector]
        Parser[IP Parser]
        Validator[Data Validator]
    end

    subgraph "Processing Pipeline"
        Enricher[Geo Data Enricher]
        Normalizer[Data Normalizer]
        Aggregator[Data Aggregator]
    end

    subgraph "Storage Pipeline"
        HotStore[Redis Hot Store]
        WarmStore[PostgreSQL]
        ColdStore[S3/Data Lake]
    end

    subgraph "Serving Pipeline"
        API[API Endpoint]
        Cache[Cache Layer]
        CDN[CDN Edge]
    end

    Source --> Collector
    Collector --> Parser
    Parser --> Validator
    Validator --> Enricher
    Enricher --> Normalizer
    Normalizer --> Aggregator
    Aggregator --> HotStore
    Aggregator --> WarmStore
    Aggregator --> ColdStore
    HotStore --> API
    WarmStore --> API
    API --> Cache
    Cache --> CDN
    CDN --> User
```

## Deployment Architecture

```mermaid
graph TB
    subgraph "Production Environment"
        subgraph "Kubernetes Cluster"
            subgraph "Ingress"
                Ingress[NGINX Ingress Controller]
            end
            
            subgraph "API Services"
                Pod1[Geo IP Pod 1]
                Pod2[Geo IP Pod 2]
                Pod3[Geo IP Pod 3]
            end
            
            subgraph "Database Services"
                RedisPod[Redis Pod]
                PostgreSQLPod[PostgreSQL Pod]
            end
        end
        
        subgraph "External Services"
            CloudSQL[Cloud SQL]
            ElastiCache[ElastiCache]
        end
    end

    subgraph "CDN Layer"
        CDN[Cloudflare/CloudFront]
    end

    User --> CDN
    CDN --> Ingress
    Ingress --> Pod1
    Ingress --> Pod2
    Ingress --> Pod3
    Pod1 --> RedisPod
    Pod2 --> RedisPod
    Pod3 --> RedisPod
    Pod1 --> PostgreSQLPod
    Pod2 --> PostgreSQLPod
    Pod3 --> PostgreSQLPod
    RedisPod --> ElastiCache
    PostgreSQLPod --> CloudSQL
```

## Error Handling Flow

```mermaid
graph TD
    Start[Request Received] --> Validate{Validate Input}
    Validate -->|Invalid| Error1[Return 400 Bad Request]
    Validate -->|Valid| Auth{Authenticate}
    Auth -->|Failed| Error2[Return 401 Unauthorized]
    Auth -->|Success| RateLimit{Check Rate Limit}
    RateLimit -->|Exceeded| Error3[Return 429 Too Many Requests]
    RateLimit -->|OK| Cache{Check Cache}
    Cache -->|Hit| Success[Return Cached Data]
    Cache -->|Miss| DB{Query Database}
    DB -->|Success| UpdateCache[Update Cache]
    DB -->|Failure| External{Query External API}
    External -->|Success| StoreDB[Store in DB]
    External -->|Failure| Error4[Return 503 Service Unavailable]
    UpdateCache --> Success
    StoreDB --> UpdateCache
    Error1 --> Log[Log Error]
    Error2 --> Log
    Error3 --> Log
    Error4 --> Log
    Log --> Monitor[Send to Monitoring]
```

## API Endpoint Architecture

```mermaid
graph LR
    subgraph "REST API Endpoints"
        GET_IP[GET /api/v1/ip/{ip_address}]
        GET_BATCH[GET /api/v1/ip/batch]
        GET_SELF[GET /api/v1/ip/self]
        POST_LOOKUP[POST /api/v1/lookup]
    end

    subgraph "GraphQL Endpoints"
        GraphQL[POST /graphql]
    end

    subgraph "WebSocket Endpoints"
        WS[WS /api/v1/stream]
    end

    subgraph "Response Formats"
        JSON[JSON]
        XML[XML]
        CSV[CSV]
    end

    GET_IP --> JSON
    GET_BATCH --> JSON
    GET_BATCH --> CSV
    GET_SELF --> JSON
    POST_LOOKUP --> JSON
    GraphQL --> JSON
    WS --> JSON
```

## Security Architecture

```mermaid
graph TB
    subgraph "Security Layers"
        WAF[Web Application Firewall]
        DDoS[DDoS Protection]
        RateLimit[Rate Limiting]
        Auth[Authentication]
        AuthZ[Authorization]
        Encryption[Encryption]
    end

    subgraph "Data Protection"
        Masking[Data Masking]
        Anonymization[IP Anonymization]
        Retention[Data Retention Policy]
        Compliance[GDPR/CCPA Compliance]
    end

    Request[Incoming Request] --> WAF
    WAF --> DDoS
    DDoS --> RateLimit
    RateLimit --> Auth
    Auth --> AuthZ
    AuthZ --> Encryption
    Encryption --> Service[Geo IP Service]
    Service --> Masking
    Masking --> Anonymization
    Anonymization --> Retention
    Retention --> Compliance
    Compliance --> Response[Response]
```

## Current Implementation Notes

### Cache Implementation

The architecture diagrams above show Redis as the cache layer, which is the intended design for production multi-process deployments. However, the current implementation (`cybersec/core/tools/geoip.py`) uses an **in-memory LRU cache** with the following characteristics:

- **Type**: Process-local `OrderedDict`-based LRU cache
- **Max Size**: Configurable via `GEOIP_CACHE_MAX_ENTRIES` (default: 10,000)
- **TTL**: Configurable via `GEOIP_CACHE_TTL_SECONDS` (default: 3600)
- **Eviction**: LRU-style eviction when max size is exceeded
- **Cleanup**: Periodic background sweep every `GEOIP_CACHE_SWEEP_INTERVAL_SECONDS` (default: 300) to remove expired entries

### Process-Local Limitations

**Important**: The current in-memory cache is **process-local**. If the application runs as:
- Multiple worker processes (e.g., gunicorn with multiple workers)
- Multiple instances behind a load balancer
- Multiple containers in a Kubernetes deployment

Then each process/instance will have its own independent cache with the following implications:

1. **Cache Isolation**: A cache hit in one process is invisible to other processes
2. **Request Volume Undercounting**: The module's rate limiter (`GEOIP_RATE_LIMIT_PER_MINUTE`) is also process-local, so actual upstream request volume to GeoIP providers is undercounted
3. **Memory Duplication**: Each process maintains its own cache copy, increasing total memory usage
4. **Inconsistent Results**: Different processes may return different results for the same IP if their caches are at different states

### Migration Path to Redis

For multi-process deployments, the cache should be migrated to Redis to match the architecture shown in the diagrams. This would:

- Provide a shared cache across all processes/instances
- Enable accurate rate limiting across the entire deployment
- Reduce total memory usage
- Ensure consistent results across all instances

The migration would involve replacing the `_LRUCache` class in `geoip.py` with a Redis-backed implementation using the existing `redis` dependency (already in `pyproject.toml`).
