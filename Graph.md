
graph TB
    subgraph INTERNET["🌐 Internet Zone — untrusted"]
        BROWSER["Browser / Mobile"]
        PSP["PSP Sandbox\nStripe · Adyen"]
        ACS["3DS ACS Server"]
        IGW["Internet GW + NAT GW\nhost port bind :443"]
    end

    FW_EDGE["⚙️ FW-EDGE\niptables · allow :443 inbound only"]

    subgraph DMZ["🔶 DMZ — 172.20.0.0/24  |  Edge network · TLS termination"]
        NGINX["Nginx Reverse Proxy\nTLS termination :443"]
        WAF["WAF / Rate Limiter\nOWASP rules · DDoS"]
        LB["Load Balancer\nRound-robin :80"]
    end

    FW_INT["⚙️ FW-INT\nDMZ → App · whitelist port only · block reverse"]

    subgraph APP["🟦 Application Network — 172.21.0.0/24  |  JWT · OAuth2 · mTLS internal"]
        APIGW["API Gateway\nJWT · HMAC verify :8080"]
        ORDER["Order Service\n:8081"]
        PAYORCH["Payment Orchestrator\nmTLS → PSP :8082"]
        FRAUD["Fraud Engine\nRule + ML :8083"]
        RECON["Recon Worker\nbatch :8084"]
    end

    FW_CDE["🔒 FW-CDE\nAllowlist: Orchestrator IP only · PKCS#11 port"]

    subgraph CDE["🔴 CDE — 172.22.0.0/24  |  PCI-DSS scope · highest trust"]
        HSM["SoftHSM / KMS\nPKCS#11 · key wrap · sign"]
        TOKENDB["Token Vault DB\nPostgres · encrypted at rest"]
        AUDITLOG["Immutable Audit Log\nJWS-signed · append-only"]
    end

    subgraph DATA["⚙️ Data / Infra Network — 172.23.0.0/24  |  no direct CDE access"]
        KAFKA["Kafka Broker\nevent bus :9092"]
        APPDB["App Database\nPostgres :5433"]
        REDIS["Redis\nrate limit · cache :6379"]
        SIEM["SIEM / ELK Stack\nPrometheus · Grafana :5601"]
    end

    subgraph MGMT["🟣 Management Zone — 172.24.0.0/24"]
        BASTION["Bastion Host\nSSH jump server"]
        CICD["CI/CD Pipeline\nartifact signing · SRI"]
        HSMADMIN["HSM Admin Console\nkey rotation · audit"]
    end

    %% ── Traffic flow ──
    BROWSER  -->|"HTTPS :443"| IGW
    IGW      -->|"forward"| FW_EDGE
    FW_EDGE  -->|"allow :443"| NGINX
    NGINX    --> WAF
    WAF      --> LB
    LB       --> FW_INT
    FW_INT   -->|"allow :8080"| APIGW

    APIGW    --> ORDER
    APIGW    --> FRAUD
    ORDER    --> PAYORCH
    PAYORCH  -.->|"mTLS :443"| PSP
    PAYORCH  -.->|"mTLS :443"| ACS

    ORDER    -->|"publish"| KAFKA
    PAYORCH  -->|"publish"| KAFKA
    KAFKA    -->|"consume"| RECON
    KAFKA    -->|"consume"| FRAUD

    APIGW    --- REDIS
    FRAUD    --- REDIS
    ORDER    --- APPDB

    PAYORCH  -.->|"FW-CDE"| FW_CDE
    FW_CDE   -.->|"PKCS#11"| HSM
    FW_CDE   -.->|"token lookup"| TOKENDB
    ORDER    -.->|"append-only"| AUDITLOG
    PAYORCH  -.->|"append-only"| AUDITLOG

    AUDITLOG -.->|"index"| SIEM
    SIEM     -.->|"read-only scrape"| APIGW
    SIEM     -.->|"read-only scrape"| PAYORCH
    SIEM     -.->|"read-only scrape"| FRAUD

    BASTION  -.->|"SSH · restricted"| CDE
    HSMADMIN -.->|"key ops"| HSM
    CICD     -.->|"deploy · signed"| APP

    %% ── Styling ──
    classDef ext   fill:#f5f0ff,stroke:#8b5cf6,color:#3b1f8c
    classDef fw    fill:#fff7ed,stroke:#d97706,color:#78350f
    classDef dmz   fill:#fffbeb,stroke:#f59e0b,color:#78350f
    classDef app   fill:#eff6ff,stroke:#3b82f6,color:#1e3a8a
    classDef cde   fill:#fef2f2,stroke:#ef4444,color:#7f1d1d
    classDef data  fill:#f0fdf4,stroke:#22c55e,color:#14532d
    classDef mgmt  fill:#faf5ff,stroke:#a855f7,color:#4a1d96

    class BROWSER,PSP,ACS,IGW ext
    class FW_EDGE,FW_INT fw
    class NGINX,WAF,LB dmz
    class APIGW,ORDER,PAYORCH,FRAUD,RECON app
    class FW_CDE,HSM,TOKENDB,AUDITLOG cde
    class KAFKA,APPDB,REDIS,SIEM data
    class BASTION,CICD,HSMADMIN mgmt
