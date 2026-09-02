# Security Implementation

Sentinel SOA employs a multi-layered security approach to protect its various components and ensure data integrity and access control. This document details the implementation of HMAC for telemetry, JWT for user authentication, and Role-Based Access Control (RBAC) for authorization.

## 1. Telemetry Ingestion Security (HMAC-SHA256)

To ensure that telemetry data originates from authorized sources (e.g., the `victim_app` and `log_shipper`), incoming telemetry batches are protected using HMAC-SHA256 signatures. This mechanism verifies both the authenticity and integrity of the data.

**Mechanism:**

*   **Request Headers:** Telemetry clients include three specific headers with each batch request:
    *   `X-Public-Key`: A public identifier for the client (e.g., `victim-app-01`).
    *   `X-Signature`: The HMAC-SHA256 signature of the request payload.
    *   `X-Timestamp`: The Unix timestamp (seconds since epoch) when the request was signed.
*   **Message Construction:** The message that is signed is constructed by concatenating the timestamp and the raw request body: `f"{timestamp}:{request_body}"`.
*   **Shared Secret:** The server stores a shared secret key for each `X-Public-Key` (client ID). This secret is used to generate the expected HMAC signature.
*   **Signature Verification:** The `Core Orchestrator` recalculates the HMAC-SHA256 signature using the received `X-Public-Key`'s corresponding secret, the `X-Timestamp`, and the request body. It then compares this calculated signature with the `X-Signature` provided by the client using a constant-time comparison to mitigate timing attacks.
*   **Replay Attack Prevention:** The `X-Timestamp` is checked against a configurable replay window. If the request's timestamp is too old or too far in the future, the request is rejected, preventing attackers from re-sending old signed telemetry batches.
*   **FastAPI Dependency:** The `verify_hmac_signature_header` FastAPI dependency abstracts this verification logic and is applied to all telemetry ingestion endpoints.

*Relevant Files:*
*   `core_orchestrator/infrastructure/security/jwt_utils.py` (HMAC logic)
*   `core_orchestrator/infrastructure/security/dependencies.py` (FastAPI `verify_hmac_signature_header`)
*   `core_orchestrator/infrastructure/security/signature_verifier.py` (Port implementation)

## 2. User Authentication (JSON Web Tokens - JWT)

User authentication for the web frontend and API access is managed using JWTs. This provides a stateless mechanism for verifying user identity after initial login.

**Mechanism:**

*   **Login Flow:** Upon successful login to the `/api/v1/auth/token` endpoint (protected by `OAuth2PasswordBearer`), the `Core Orchestrator` issues an access token (JWT) to the user.
*   **Token Payload:** The JWT contains essential user information as claims:
    *   `sub`: User ID.
    *   `username`: User's username.
    *   `role`: User's assigned role (e.g., "admin", "analyst", "user").
    *   `exp`: Expiration timestamp of the token.
    *   `iat`: Issued-at timestamp.
    *   `jti`: A unique JWT ID, crucial for token revocation (see next section).
*   **Token Usage:** For subsequent requests to protected endpoints, the client includes this JWT in the `Authorization` header as a Bearer token.
*   **Token Validation:** The `get_current_user` FastAPI dependency intercepts these requests, decodes the token, verifies its signature (ensuring it hasn't been tampered with), checks its expiration, and consults a blacklist (for logout functionality).

*Relevant Files:*
*   `core_orchestrator/infrastructure/security/jwt_utils.py` (JWT encoding/decoding)
*   `core_orchestrator/infrastructure/security/token_service.py` (Port implementation)
*   `core_orchestrator/infrastructure/security/dependencies.py` (FastAPI `get_current_user`)

## 3. Authorization (Role-Based Access Control - RBAC)

Sentinel SOA implements RBAC to restrict access to specific API endpoints based on the authenticated user's role. This is enforced directly through FastAPI dependencies.

**Mechanism:**

*   **Role Assignment:** Each user is assigned a specific role (e.g., "admin", "analyst", "user"). This role is stored in the user's record in the database and included as a `role` claim in their JWT.
*   **Role-Specific Dependencies:**
    *   `get_admin_user`: This dependency builds upon `get_current_user`. If the authenticated user does not have the "admin" role, a `403 Forbidden` HTTP exception is raised.
    *   `get_analyst_user`: This dependency also builds upon `get_current_user`. It grants access if the authenticated user has either the "admin" or "analyst" role.
* **Endpoint Protection:** By applying these role-specific dependencies to FastAPI route functions, access is automatically restricted. For example:
  ```python
  @router.get("/admin_only_data", dependencies=[Depends(get_admin_user)])
  async def get_sensitive_data():
      pass
  ```

*Relevant Files:*
*   `core_orchestrator/domain/models/auth/user.py` (User model with `role` field)
*   `core_orchestrator/infrastructure/security/dependencies.py` (FastAPI `get_admin_user`, `get_analyst_user`)
