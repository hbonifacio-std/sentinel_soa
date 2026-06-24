import logging
import json
import os
import sys
import time
import urllib
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional

from fastapi import FastAPI, Request, Depends, HTTPException, status, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt 
from pydantic import BaseModel
import hmac
import hashlib
from urllib import request as urllib_request
from urllib import error as urllib_error

# --- Logging Configuration ---
# Configures the logger to write to a specific file.
log_path = "/var/log/victim_app/activity.log"
#log_path = os.getenv("LOG_PATH", "activity.log")
file_handler = logging.FileHandler(log_path)
file_handler.setFormatter(logging.Formatter('%(message)s'))

activity_logger = logging.getLogger("victim_app_activity")
activity_logger.setLevel(logging.INFO)
activity_logger.addHandler(file_handler)
activity_logger.propagate = False

# --- Unique identifier for this application ---
SOURCE_ID = os.getenv("VICTIM_SOURCE_ID", "victim-app-01")
APP_NAME = os.getenv("APP_NAME", "Core-Banking-API")
APP_VERSION = os.getenv("APP_VERSION", "2.4.1")
APP_ENV = os.getenv("APP_ENV", "development")

# --- Telemetry Forwarding Security Configuration ---
TELEMETRY_FORWARD_URL = os.getenv(
    "TELEMETRY_FORWARD_URL",
    "http://core:8000/api/v1/telemetry/ingest/batch",
)
TELEMETRY_HMAC_PUBLIC_KEY = os.getenv("TELEMETRY_HMAC_PUBLIC_KEY", "victim-app-key")
TELEMETRY_HMAC_SECRET = os.getenv("TELEMETRY_HMAC_SECRET", "victim-app-secret-for-telemetry")
VECTOR_INTERNAL_TOKEN = os.getenv("VECTOR_INTERNAL_TOKEN", "vector-internal-dev-token")

# --- Security and Authentication Configuration ---
SECRET_KEY = "a_very_secret_key_for_a_vulnerable_app" # Secret key for signing JWT
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# In-memory user database (simulation)
FAKE_USERS_DB = {
    "alice": {"username": "alice", "full_name": "Alice Smith", "password": "password123", "role": "user"},
    "bob": {"username": "bob", "full_name": "Bob Johnson", "password": "secure_password", "role": "user"},
    "charlie": {"username": "charlie", "full_name": "Charlie Brown", "password": "pass", "role": "user"},
    "admin": {"username": "admin", "full_name": "Admin User", "password": "admin_password_!@#", "role": "admin"},
    "guest": {"username": "guest", "full_name": "Guest User", "password": "guest", "role": "guest"},
}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

class TokenData(BaseModel):
    username: Optional[str] = None

# --- Authentication Utility Functions ---
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = FAKE_USERS_DB.get(token_data.username)
    if user is None:
        raise credentials_exception
    return user

# --- FastAPI App Initialization ---
app = FastAPI(title="Victim App", description="A vulnerable application for security simulation.")

# --- Request Logging Middleware ---
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    path = request.url.path

    # 1. Captura rápida de red (No bloqueante)
    forwarded_for = request.headers.get("x-forwarded-for")
    real_ip = request.headers.get("x-real-ip")
    client_ip = forwarded_for.split(",")[0].strip() if forwarded_for else (real_ip or request.client.host)
    client_port = request.client.port if request.client else None
    server_port = request.url.port or (443 if request.url.scheme == "https" else 80)
    # 2. Sanitización CONDICIONAL (Solo si es la ruta crítica de Login)
    # Evitamos leer el body en el 95% de las peticiones de la app
    attempted_username = None
    http_body = None

    if path == "/auth/login":
        content_type = request.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" in content_type:
            try:
                # Solo leemos el body si es estrictamente el login
                raw_body = await request.body()
                body_str = raw_body.decode('utf-8', errors='ignore')

                # Parseo rápido
                import urllib.parse
                parsed_form = urllib.parse.parse_qs(body_str)
                if "username" in parsed_form:
                    attempted_username = parsed_form["username"][0]

                # Ofuscación rápida sin reconstruir todo el formulario
                http_body = "username=" + (attempted_username or "unknown") + "&password=[REDACTED]"
            except Exception:
                attempted_username = "error_parsing"
                http_body = "[ERROR_PARSING_LOGIN]"

    # 3. Extraer JWT rápidamente sin validar firmas (Solo lectura de payload)
    authenticated_user = None
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.startswith("Bearer "):
        try:
            token = auth_header.split(" ")[1]
            # Usar PyJWT o python-jose de forma directa optimizada
            payload = jwt.decode(token, options={"verify_signature": False})
            authenticated_user = payload.get("sub")
        except Exception:
            authenticated_user = "invalid_token"

    # --- Procesar la petición original ---
    response = await call_next(request)
    process_time = time.time() - start_time
    process_time_ms = round(process_time * 1000, 2)

    # 4. Extracción de Headers de Respuesta y Petición para completar campos
    response_content_type = response.headers.get("content-type")
    response_size = response.headers.get("content-length")

    # 4. Construcción del JSON minimalista
    log_data = {
        "source_id": SOURCE_ID,
        "source_ip": client_ip,
        "timestamp": datetime.now(timezone.utc).isoformat(),

        "network":{
            "client_ip":client_ip,
            "client_port":client_port,
            "server_port":server_port,
            "proxy_forwarded_for":forwarded_for,
            "proxy_real_ip":real_ip
        },

        "http": {
            "method": request.method,
            "path": path,
            "query":request.url.query or None,
            "status_code": response.status_code,
            "processing_time_ms": process_time_ms,
            "content_type":response_content_type,
            "user_agent": request.headers.get("user-agent"),
            "referrer":request.headers.get("referer"),
            "response_size_bytes":int(response_size) if response_size else None,
            "payload":http_body
        },
        "host":{
            "pid":os.getpid(),
            "process_name":"uvicorn/gunicorn",
            "process_time_ms":process_time_ms,
            "environment":os.getenv("APP_ENV", "development")
        },
        "extra_fields":{
            "user": {
                "authenticated_id": authenticated_user,
                "attempted_username": attempted_username
            },
        }
    }

    # 5. Grabación en Log
    # NOTA: Asegúrate de que tu activity_logger use un Handler asíncrono o una cola en memoria
    activity_logger.info(json.dumps(log_data))

    return response

# --- API Endpoints ---
@app.get("/", tags=["General"])
async def read_root():
    """Welcome endpoint to simulate benign traffic."""
    return {"message": "Welcome to the vulnerable application!"}

@app.post("/auth/login", tags=["Authentication"])
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Authentication endpoint. Accepts 'username' and 'password'.
    Vulnerable to user enumeration and brute force attacks.
    """
    user = FAKE_USERS_DB.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/users/me", tags=["User"])
async def read_users_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Protected endpoint that returns the current user's information."""
    return current_user

@app.get("/api/products", tags=["Products"])
async def get_products(token: str = Depends(oauth2_scheme)):
    """Protected endpoint that lists products. Requires authentication."""
    return [
        {"id": 1, "name": "Secure Widget", "price": 100.0},
        {"id": 2, "name": "Vulnerable Gadget", "price": 25.5},
    ]


if __name__ == "__main__":
    import uvicorn
    # Explicit local launch for debugging in development
    uvicorn.run("main:app", host="0.0.0.0", port=8002, reload=True)