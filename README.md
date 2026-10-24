# FinanceFlow Identity Service

Standalone Java 21 / Spring Boot identity service, isolated from the existing FinanceFlow application.

## Features
- User registration and login
- BCrypt password hashing
- Signed JWT access tokens
- `GET /api/v1/users/me` derives identity from the verified token
- PostgreSQL for local use; H2 for tests
- Integration tests for registration, duplicate email, login/profile and authentication requirement
- Runs on port 8081 (existing FinanceFlow uses 8080)

## Setup
Create a PostgreSQL database:
```sql
CREATE DATABASE financeflow_identity;
```

Set local environment variables:
```bash
export DB_URL='jdbc:postgresql://localhost:5432/financeflow_identity'
export DB_USERNAME='your_postgres_user'
export DB_PASSWORD='your_postgres_password'
export JWT_SECRET="$(openssl rand -base64 48)"
```

Run with Maven:
```bash
mvn spring-boot:run
```
If Maven isn't installed, open as a Maven project in VS Code or generate a Maven wrapper with `mvn wrapper:wrapper`, then use `./mvnw spring-boot:run`.

## API
Register:
`POST http://localhost:8081/api/v1/auth/register`
```json
{"email":"person@example.com","password":"ChangeMe123!","displayName":"Demo User"}
```

Login:
`POST http://localhost:8081/api/v1/auth/login`
```json
{"email":"person@example.com","password":"ChangeMe123!"}
```
Copy `accessToken` from the response.

Profile:
`GET http://localhost:8081/api/v1/users/me`
Header: `Authorization: Bearer <accessToken>`

Health: `GET http://localhost:8081/actuator/health`

## Test
```bash
mvn test
```

## Security notes
This is an educational starter, not production-ready identity infrastructure. The local JWT secret fallback must be overridden outside local development. Before production, add Flyway migrations, refresh-token rotation/revocation, email verification, password reset, login throttling, audit logs, secret management, and asymmetric JWT signing/JWKS. FinanceFlow must separately validate the JWT and scope each transaction/budget query by the verified user ID; that integration is not part of this isolated service yet.
