# Vaultix Authorization Service

Authentication and Authorization microservice for the **Vaultix** platform.

---

## Service Details

- **Group ID**: `com.vaultix`
- **Artifact ID**: `authorization`
- **Version**: `0.0.1`
- **Port**: `8082` (local development)

---

## Planned Capabilities

As development progresses, this service will handle:
- User registration, login, and credential management.
- JWT issuing, validation, and token refresh mechanisms.
- Role-based and permission-based access control (RBAC).
- Session storage and token blacklisting using Redis.
- User data persistence using PostgreSQL (`vaultix_auth_db`).

---

## Running Locally

### Build
```powershell
.\mvnw.cmd clean package
```

### Run
```powershell
.\mvnw.cmd spring-boot:run
```
Service will be available at: [http://localhost:8082](http://localhost:8082)
