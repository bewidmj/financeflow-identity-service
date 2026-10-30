# FinanceFlow Identity Service

Java 21 / Spring Boot identity service for FinanceFlow. It registers and authenticates users, issues RS256 access tokens, and publishes public signing keys as a JWKS. FinanceFlow verifies tokens locally using that JWKS; the Identity Service is not contacted for each FinanceFlow API request.

## Local setup

Create the PostgreSQL database and configure the datasource in `src/main/resources/application.yml` for your local PostgreSQL instance:

```sql
CREATE DATABASE financeflow_identity;
```

Generate one local RSA key pair. Keep the private key outside both repositories, restrict its permissions, and reuse it across routine restarts:

```bash
mkdir -p "$HOME/.config/financeflow"
chmod 700 "$HOME/.config/financeflow"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out "$HOME/.config/financeflow/identity-private.pem"
openssl pkey -in "$HOME/.config/financeflow/identity-private.pem" \
  -pubout -out "$HOME/.config/financeflow/identity-public.pem"
chmod 600 "$HOME/.config/financeflow/identity-private.pem"
```

The private key is PKCS#8 PEM. Do not commit it, put it in an image, print it, or generate a replacement on each application start. The public key is derived from the configured private key; the public PEM is useful for offline inspection and future rotation.

Configure the Identity Service in its shell before starting it:

```bash
export JWT_PRIVATE_KEY_LOCATION="file:$HOME/.config/financeflow/identity-private.pem"
export JWT_KEY_ID="financeflow-local-2026-01"
export JWT_EXPIRATION_MS=3600000
```

### Provisioning a local administrator

Public registration always creates a `USER`. To provision a local development
administrator, supply an email and a strong password through the Identity
Service process environment before startup. The bootstrap creates the account
only if the email does not exist, stores a BCrypt hash, and never resets an
existing admin password. If the email already belongs to a regular account,
startup fails rather than silently elevating it. Keep the password out of
source control, shell history, and logs; use a private prompt or secret manager:

```bash
export SPRING_PROFILES_ACTIVE=local
export ADMIN_BOOTSTRAP_EMAIL="admin@example.test"
read -s -p "Local admin password: " ADMIN_BOOTSTRAP_PASSWORD
echo
export ADMIN_BOOTSTRAP_PASSWORD
export ADMIN_BOOTSTRAP_DISPLAY_NAME="Local administrator"
```

The bootstrap password must be at least 16 characters and at most 72 UTF-8
bytes. Remove the bootstrap environment variables after provisioning; the
account remains in the database. Start the service using the command below.
After its first startup, stop it and unset the bootstrap environment variables
before subsequent starts. Role changes and account deactivation are not exposed
by the service.

Optional rotation overlap keys use comma-separated `kid=file:` public-key locations:

```bash
export JWT_ADDITIONAL_PUBLIC_KEYS="financeflow-previous-2025-01=file:$HOME/.config/financeflow/identity-previous-public.pem"
```

Start the Identity Service from this repository:

```bash
mvn spring-boot:run
```

It listens on port `8081`. The FinanceFlow API listens on port `8080`.

## API and token verification

- Register: `POST http://localhost:8081/api/v1/auth/register`
- Login: `POST http://localhost:8081/api/v1/auth/login`
- Profile: `GET http://localhost:8081/api/v1/users/me`
- Admin overview: `GET http://localhost:8081/api/v1/admin/overview` (`ADMIN`)
- Search users: `GET http://localhost:8081/api/v1/admin/users` (`ADMIN`)
- User details: `GET http://localhost:8081/api/v1/admin/users/{id}` (`ADMIN`)
- Public JWKS: `GET http://localhost:8081/.well-known/jwks.json`
- Health: `GET http://localhost:8081/actuator/health`

Login continues to return `accessToken`, `tokenType`, and `expiresInSeconds`. New tokens use `RS256`, a stable `kid`, and the existing `sub` (user UUID), `email`, `role`, `iat`, and configured `exp` claims.
Admin endpoints return only account ID, email, display name, role, and creation
time; password hashes are never included. Search and user lists are paginated.
FinanceFlow separately enforces the same signed role claim for admin-only
transaction browsing.

To inspect only the token algorithm and key ID without printing the token:

```bash
ACCESS_TOKEN="$TOKEN" python3 -c 'import os,json,base64; h=os.environ["ACCESS_TOKEN"].split(".")[0]; print(json.loads(base64.urlsafe_b64decode(h+"="*((4-len(h)%4)%4))))'
```

The private-key loader accepts PKCS#8 `BEGIN PRIVATE KEY` PEM. Startup fails if the configured key is missing, malformed, non-RSA, smaller than 2048 bits, or the `kid` configuration is invalid. No production key is generated automatically.

### Troubleshooting

- **Invalid signature:** confirm the Identity Service is signing with the private key whose public key is published for that token's `kid`; do not copy a key into FinanceFlow.
- **Unknown `kid`:** confirm `JWT_KEY_ID` and JWKS agree, and that overlap public keys are included in `JWT_ADDITIONAL_PUBLIC_KEYS`. Check that the new key has propagated through JWKS caches before switching signers.
- **JWKS fetch failure:** fetch `/.well-known/jwks.json` from the FinanceFlow host/network, then check the configured URI, service DNS, TLS trust, and network policy. FinanceFlow uses short bounded connection/read timeouts.
- **Expired token:** log in again for a fresh token and confirm the clocks on both services are synchronized.

## FinanceFlow and cutover

In a second terminal, configure and start FinanceFlow:

```bash
export JWT_JWKS_URI="http://localhost:8081/.well-known/jwks.json"
cd ../financeflow
./mvnw spring-boot:run
```

Register a test user through `POST http://localhost:8081/api/v1/auth/register`, then log in through `POST http://localhost:8081/api/v1/auth/login`. Authorize FinanceFlow Swagger at `http://localhost:8080/swagger-ui/index.html` with the returned bearer token and call a protected endpoint such as `GET /api/v1/transactions`. To verify ownership, create a record as one user and confirm a second user's token cannot retrieve it. The JWKS URI is configurable for other environments, including Kubernetes service DNS.

Existing HS384 tokens are intentionally rejected after this cutover. Log in again to obtain an RS256 token; there is no shared-secret fallback.

## Rotation and deployment

The active private key and its derived public key are served under `JWT_KEY_ID`. To rotate, first add the new key's public PEM as an additional `kid=file:` entry while the old key remains active, and allow FinanceFlow JWKS caches to refresh. Then deploy the new private key with its new `JWT_KEY_ID`, retaining the old public key as an additional key. Keep every old public key published until tokens signed by it have expired plus the accepted clock-skew/rollout window. Remove it only as a deliberate configuration change. Rotation is operator-managed; automatic key rotation is not implemented.

For Kubernetes, provision the private PEM using a Kubernetes Secret or external secret manager, restrict Secret read access through namespace-scoped RBAC, and mount it read-only into the Identity Service. Set `JWT_PRIVATE_KEY_LOCATION` to the mounted path and `JWT_KEY_ID` through deployment configuration. Do not bake the key into the container image. Expose `/.well-known/jwks.json` through the Identity Service ClusterIP Service. Use TLS where traffic leaves a trusted cluster boundary and network policies that allow FinanceFlow to reach the JWKS endpoint.

FinanceFlow receives only `JWT_JWKS_URI`, for example `http://financeflow-identity-service.<namespace>.svc.cluster.local:8081/.well-known/jwks.json`; it must not receive the private key or the old `JWT_SECRET`. Keep the JWKS URI stable across independent rollouts. FinanceFlow uses a 2-second connect timeout, 5-second read timeout, and Nimbus's default JWKS cache/refresh behavior (approximately five minutes). During a temporary outage, a warm instance can validate with its cached keys until refresh is needed. A cold instance with no cached key cannot validate tokens until it can fetch the JWKS. Ensure readiness and network policy account for this behavior.

## Tests

Tests generate ephemeral RSA keys and do not require local signing material or a running Identity Service:

```bash
mvn test -q
```

The complete login-to-FinanceFlow flow can be checked manually by starting both applications, logging in through `POST /api/v1/auth/login`, and requesting a protected FinanceFlow endpoint with the returned token. Altering its signature or using the old HS384 token must result in `401 Unauthorized`.

## Operational security notes

Never log bearer tokens, passwords, the private key, or the former HS384 secret. Keep database credentials and signing material in an external secret store. This starter does not implement automated key rotation, refresh-token revocation, login throttling, audit logging, or a database migration framework.
