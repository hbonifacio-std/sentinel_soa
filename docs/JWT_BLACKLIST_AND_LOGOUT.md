# JWT Blacklist and Stateless Logout

This document details the design and implementation of the stateless JWT revocation (logout) mechanism in Sentinel SOA, which relies on a Redis-based blacklist.

## 1. The Challenge of Stateless Logout

JSON Web Tokens (JWTs) are stateless by design. Once a token is issued, it is valid until its expiration time (`exp` claim). There is no built-in way to invalidate a token on the server side before it expires. If a user's token is compromised, an attacker can use it until it expires, even if the user changes their password or logs out.

To solve this, Sentinel SOA implements a **token blacklist**.

## 2. Implementation Strategy: JTI and Redis

The core of the solution is to treat each JWT as a unique, revocable credential.

1.  **Unique Token Identifier (`jti`):** When a new JWT is created upon user login, it is assigned a unique identifier via the `jti` (JWT ID) claim. This ID is generated using `uuid.uuid4()`.

    *File reference: `core_orchestrator/infrastructure/security/jwt_utils.py` (function `create_access_token`)*

2.  **Redis Blacklist:** A Redis cache is used to store the `jti` of any token that has been revoked.

    *File reference: `core_orchestrator/infrastructure/cache/redis_token_blacklist_repository.py`*

3.  **Automatic Expiry:** When a token is added to the blacklist, its entry in Redis is set with a Time-To-Live (TTL) that matches the token's original remaining lifespan. This ensures that the blacklist doesn't grow indefinitely and automatically cleans itself up.

## 3. The Logout Flow

1.  **Request:** The user sends a request to the logout endpoint (`/api/v1/auth/logout`). The request includes their valid JWT in the `Authorization` header.

2.  **JTI Extraction:** The backend receives the token, decodes it without full validation, and extracts its `jti` claim.

    *File reference: `core_orchestrator/infrastructure/security/token_service.py` (method `get_token_jti`)*

3.  **Add to Blacklist:** The `jti` is added to the Redis blacklist. The system calculates the token's remaining validity from its `exp` claim and uses this value as the TTL for the Redis key.

    *File reference: `core_orchestrator/infrastructure/cache/redis_token_blacklist_repository.py` (method `add_to_blacklist`)*

4.  **Confirmation:** The user is logged out.

## 4. Verification on Subsequent Requests

On every subsequent request to a protected endpoint, the `get_current_user` security dependency performs the following check:

1.  It extracts the `jti` from the incoming token.
2.  It queries the Redis repository to see if the `jti` exists in the blacklist.
3.  If the `jti` is found, the token is considered revoked. The dependency raises a `401 Unauthorized` error, denying access, even if the token's signature and expiration are otherwise valid.

    *File reference: `core_orchestrator/infrastructure/security/dependencies.py` (dependency `get_current_user`)*

This approach provides a robust and efficient way to implement secure logout for a stateless authentication system.
