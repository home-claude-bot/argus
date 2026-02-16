# Argus Operating Playbook

> **Status**: Planning | **Created**: 2026-02-16 | **Author**: Boss Bot
> **Purpose**: CI/CD pipelines, deployment procedures, operational runbooks
> **Reading Time**: 20 minutes

---

## CI/CD Pipeline

### GitHub Actions Workflows

#### ci.yml - Continuous Integration

```yaml
# .github/workflows/ci.yml
name: CI

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main, develop]

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: -Dwarnings

jobs:
  lint:
    name: Lint
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2

      - name: Check formatting
        run: cargo fmt --all -- --check

      - name: Clippy
        run: cargo clippy --workspace --all-targets --all-features

      - name: Shellcheck
        uses: ludeeus/action-shellcheck@master
        with:
          scandir: './scripts'

  test:
    name: Test
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_USER: test
          POSTGRES_PASSWORD: test
          POSTGRES_DB: argus_test
        ports:
          - 5432:5432
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2

      - name: Run migrations
        run: |
          cargo install sqlx-cli --no-default-features --features postgres
          sqlx database create --database-url $DATABASE_URL
          sqlx migrate run --source migrations/auth --database-url $DATABASE_URL
          sqlx migrate run --source migrations/identity --database-url $DATABASE_URL
          sqlx migrate run --source migrations/billing --database-url $DATABASE_URL
        env:
          DATABASE_URL: postgres://test:test@localhost:5432/argus_test

      - name: Run tests
        run: cargo test --workspace
        env:
          DATABASE_URL: postgres://test:test@localhost:5432/argus_test

      - name: Run integration tests
        run: cargo test --workspace --features integration
        env:
          DATABASE_URL: postgres://test:test@localhost:5432/argus_test

  build:
    name: Build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2

      - name: Build release
        run: cargo build --release --workspace

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: binaries
          path: |
            target/release/auth-api
            target/release/identity-api
            target/release/billing-api

  security:
    name: Security Audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: Install cargo-audit
        run: cargo install cargo-audit

      - name: Run audit
        run: cargo audit

      - name: Install cargo-deny
        run: cargo install cargo-deny

      - name: Check licenses and advisories
        run: cargo deny check

  web:
    name: Web Dashboard
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: web/dashboard
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
          cache-dependency-path: web/dashboard/package-lock.json

      - name: Install dependencies
        run: npm ci

      - name: Lint
        run: npm run lint

      - name: Type check
        run: npm run typecheck

      - name: Test
        run: npm run test

      - name: Build
        run: npm run build
```

#### cd.yml - Continuous Deployment

```yaml
# .github/workflows/cd.yml
name: CD

on:
  push:
    branches: [main]
  workflow_dispatch:
    inputs:
      environment:
        description: 'Deploy environment'
        required: true
        default: 'staging'
        type: choice
        options:
          - staging
          - production

env:
  AWS_REGION: us-east-1
  ECR_REGISTRY: ${{ secrets.ECR_REGISTRY }}

jobs:
  build-push:
    name: Build and Push Images
    runs-on: ubuntu-latest
    outputs:
      image_tag: ${{ steps.meta.outputs.tags }}
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ env.AWS_REGION }}

      - name: Login to ECR
        uses: aws-actions/amazon-ecr-login@v2

      - name: Extract metadata
        id: meta
        run: echo "tags=${{ github.sha }}" >> $GITHUB_OUTPUT

      - name: Build and push auth-api
        uses: docker/build-push-action@v5
        with:
          context: .
          file: services/auth-api/Dockerfile
          push: true
          tags: ${{ env.ECR_REGISTRY }}/argus-auth-api:${{ github.sha }}

      - name: Build and push identity-api
        uses: docker/build-push-action@v5
        with:
          context: .
          file: services/identity-api/Dockerfile
          push: true
          tags: ${{ env.ECR_REGISTRY }}/argus-identity-api:${{ github.sha }}

      - name: Build and push billing-api
        uses: docker/build-push-action@v5
        with:
          context: .
          file: services/billing-api/Dockerfile
          push: true
          tags: ${{ env.ECR_REGISTRY }}/argus-billing-api:${{ github.sha }}

      - name: Build and push dashboard
        uses: docker/build-push-action@v5
        with:
          context: web/dashboard
          push: true
          tags: ${{ env.ECR_REGISTRY }}/argus-dashboard:${{ github.sha }}

  deploy-staging:
    name: Deploy to Staging
    needs: build-push
    runs-on: ubuntu-latest
    environment: staging
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ env.AWS_REGION }}

      - name: Update kubeconfig
        run: aws eks update-kubeconfig --name argus-staging

      - name: Deploy auth-api
        run: |
          kubectl set image deployment/argus-auth-api \
            auth-api=${{ env.ECR_REGISTRY }}/argus-auth-api:${{ github.sha }} \
            -n argus

      - name: Deploy identity-api
        run: |
          kubectl set image deployment/argus-identity-api \
            identity-api=${{ env.ECR_REGISTRY }}/argus-identity-api:${{ github.sha }} \
            -n argus

      - name: Deploy billing-api
        run: |
          kubectl set image deployment/argus-billing-api \
            billing-api=${{ env.ECR_REGISTRY }}/argus-billing-api:${{ github.sha }} \
            -n argus

      - name: Run smoke tests
        run: ./scripts/smoke-test.sh staging

  deploy-production:
    name: Deploy to Production
    needs: [build-push, deploy-staging]
    runs-on: ubuntu-latest
    environment: production
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ env.AWS_REGION }}

      - name: Update kubeconfig
        run: aws eks update-kubeconfig --name argus-production

      - name: Blue-green deployment
        run: |
          # Update blue deployment
          kubectl set image deployment/argus-auth-api-blue \
            auth-api=${{ env.ECR_REGISTRY }}/argus-auth-api:${{ github.sha }} \
            -n argus

          # Wait for rollout
          kubectl rollout status deployment/argus-auth-api-blue -n argus

          # Switch traffic
          kubectl patch service argus-auth-api \
            -p '{"spec":{"selector":{"version":"blue"}}}' -n argus

      - name: Health check
        run: ./scripts/health-check.sh production
```

#### release.yml - Release Management

```yaml
# .github/workflows/release.yml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  release:
    name: Create Release
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Generate changelog
        id: changelog
        uses: orhun/git-cliff-action@v3
        with:
          config: cliff.toml
          args: --latest --strip header

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v1
        with:
          body: ${{ steps.changelog.outputs.content }}
          draft: false
          prerelease: ${{ contains(github.ref, '-rc') }}

      - name: Build release images
        run: |
          docker build -t argus-auth-api:${{ github.ref_name }} -f services/auth-api/Dockerfile .
          docker build -t argus-billing-api:${{ github.ref_name }} -f services/billing-api/Dockerfile .

      - name: Push release images
        run: |
          docker tag argus-auth-api:${{ github.ref_name }} ${{ env.ECR_REGISTRY }}/argus-auth-api:${{ github.ref_name }}
          docker push ${{ env.ECR_REGISTRY }}/argus-auth-api:${{ github.ref_name }}
```

---

## Dockerfiles

### Auth API

```dockerfile
# services/auth-api/Dockerfile
FROM rust:1.78-slim-bookworm AS builder

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY services/ services/

# Build release
RUN cargo build --release --package auth-api

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/auth-api /usr/local/bin/

EXPOSE 8080 9090

CMD ["auth-api"]
```

### Identity API

```dockerfile
# services/identity-api/Dockerfile
FROM rust:1.78-slim-bookworm AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY services/ services/

RUN cargo build --release --package identity-api

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/identity-api /usr/local/bin/

EXPOSE 8081 9091

CMD ["identity-api"]
```

### Billing API

```dockerfile
# services/billing-api/Dockerfile
FROM rust:1.78-slim-bookworm AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY services/ services/

RUN cargo build --release --package billing-api

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/billing-api /usr/local/bin/

EXPOSE 8082 9092

CMD ["billing-api"]
```

---

## Kubernetes Manifests

### Auth API Deployment

```yaml
# deploy/k8s/auth-api/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: argus-auth-api
  namespace: argus
spec:
  replicas: 3
  selector:
    matchLabels:
      app: argus-auth-api
  template:
    metadata:
      labels:
        app: argus-auth-api
    spec:
      containers:
        - name: auth-api
          image: ${ECR_REGISTRY}/argus-auth-api:latest
          ports:
            - containerPort: 8080
              name: http
            - containerPort: 9090
              name: grpc
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: argus-secrets
                  key: database-url
            - name: COGNITO_POOL_ID
              valueFrom:
                configMapKeyRef:
                  name: argus-config
                  key: cognito-pool-id
          resources:
            requests:
              cpu: 100m
              memory: 256Mi
            limits:
              cpu: 500m
              memory: 512Mi
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: argus-auth-api
  namespace: argus
spec:
  selector:
    app: argus-auth-api
  ports:
    - name: http
      port: 80
      targetPort: 8080
    - name: grpc
      port: 9090
      targetPort: 9090
```

### Identity API Deployment

```yaml
# deploy/k8s/identity-api/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: argus-identity-api
  namespace: argus
spec:
  replicas: 3
  selector:
    matchLabels:
      app: argus-identity-api
  template:
    metadata:
      labels:
        app: argus-identity-api
    spec:
      containers:
        - name: identity-api
          image: ${ECR_REGISTRY}/argus-identity-api:latest
          ports:
            - containerPort: 8081
              name: http
            - containerPort: 9091
              name: grpc
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: argus-secrets
                  key: database-url
            - name: AUTH_SERVICE_URL
              value: "http://argus-auth-api:9090"
          resources:
            requests:
              cpu: 100m
              memory: 256Mi
            limits:
              cpu: 500m
              memory: 512Mi
          livenessProbe:
            httpGet:
              path: /health
              port: 8081
            initialDelaySeconds: 10
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /ready
              port: 8081
            initialDelaySeconds: 5
            periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: argus-identity-api
  namespace: argus
spec:
  selector:
    app: argus-identity-api
  ports:
    - name: http
      port: 80
      targetPort: 8081
    - name: grpc
      port: 9091
      targetPort: 9091
```

### Billing API Deployment

```yaml
# deploy/k8s/billing-api/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: argus-billing-api
  namespace: argus
spec:
  replicas: 3
  selector:
    matchLabels:
      app: argus-billing-api
  template:
    metadata:
      labels:
        app: argus-billing-api
    spec:
      containers:
        - name: billing-api
          image: ${ECR_REGISTRY}/argus-billing-api:latest
          ports:
            - containerPort: 8082
              name: http
            - containerPort: 9092
              name: grpc
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: argus-secrets
                  key: database-url
            - name: AUTH_SERVICE_URL
              value: "http://argus-auth-api:9090"
            - name: IDENTITY_SERVICE_URL
              value: "http://argus-identity-api:9091"
            - name: STRIPE_SECRET_KEY
              valueFrom:
                secretKeyRef:
                  name: argus-secrets
                  key: stripe-secret-key
          resources:
            requests:
              cpu: 100m
              memory: 256Mi
            limits:
              cpu: 500m
              memory: 512Mi
          livenessProbe:
            httpGet:
              path: /health
              port: 8082
            initialDelaySeconds: 10
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /ready
              port: 8082
            initialDelaySeconds: 5
            periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: argus-billing-api
  namespace: argus
spec:
  selector:
    app: argus-billing-api
  ports:
    - name: http
      port: 80
      targetPort: 8082
    - name: grpc
      port: 9092
      targetPort: 9092
```

---

## Operational Runbooks

### Runbook: Database Migration

```bash
#!/bin/bash
# scripts/migrate.sh

set -euo pipefail

ENV=${1:-staging}
SERVICE=${2:-all}

# Load environment
source "./deploy/env/${ENV}.env"

# Run migrations
if [[ "$SERVICE" == "auth" || "$SERVICE" == "all" ]]; then
    echo "Running auth migrations..."
    sqlx migrate run --source migrations/auth --database-url "$AUTH_DATABASE_URL"
fi

if [[ "$SERVICE" == "identity" || "$SERVICE" == "all" ]]; then
    echo "Running identity migrations..."
    sqlx migrate run --source migrations/identity --database-url "$IDENTITY_DATABASE_URL"
fi

if [[ "$SERVICE" == "billing" || "$SERVICE" == "all" ]]; then
    echo "Running billing migrations..."
    sqlx migrate run --source migrations/billing --database-url "$BILLING_DATABASE_URL"
fi

echo "Migrations complete"
```

### Runbook: Service Restart

```bash
#!/bin/bash
# scripts/restart-service.sh

set -euo pipefail

SERVICE=$1
ENV=${2:-staging}

echo "Restarting $SERVICE in $ENV..."

kubectl rollout restart deployment/argus-$SERVICE -n argus
kubectl rollout status deployment/argus-$SERVICE -n argus --timeout=300s

echo "Service restarted successfully"
```

### Runbook: Rollback

```bash
#!/bin/bash
# scripts/rollback.sh

set -euo pipefail

SERVICE=$1
REVISION=${2:-1}

echo "Rolling back $SERVICE to revision $REVISION..."

kubectl rollout undo deployment/argus-$SERVICE -n argus --to-revision=$REVISION
kubectl rollout status deployment/argus-$SERVICE -n argus --timeout=300s

echo "Rollback complete"
```

---

## Monitoring & Alerting

### Health Check Endpoints

Each service exposes:

| Endpoint | Purpose |
|----------|---------|
| `GET /health` | Liveness probe (is the process running?) |
| `GET /ready` | Readiness probe (can it handle traffic?) |
| `GET /metrics` | Prometheus metrics |

### Key Metrics

| Metric | Alert Threshold |
|--------|----------------|
| Request latency p99 | > 500ms |
| Error rate | > 1% |
| CPU usage | > 80% |
| Memory usage | > 80% |
| Database connections | > 80% pool |

### Grafana Dashboards

- Service Overview: Request rate, latency, errors
- Database: Query times, connections, slow queries
- Business: Subscriptions, tier distribution, revenue

---

## Incident Response

### Severity Levels

| Level | Description | Response Time |
|-------|-------------|---------------|
| SEV1 | Service down | 15 minutes |
| SEV2 | Degraded performance | 1 hour |
| SEV3 | Minor issue | 4 hours |
| SEV4 | Low priority | 24 hours |

### On-Call Escalation

1. Bot attempts auto-remediation
2. Alert to #bot-alerts if unresolved
3. Human escalation for SEV1/SEV2

---

*Next: Review [Appendices](argus-appendices.md) for migration guides and resources.*
