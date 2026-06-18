import logging
import json
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional

from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt 
from pydantic import BaseModel

# --- Configuración de Logging ---
# Configura el logger para escribir en un archivo específico.
log_path = "/var/log/victim_app/activity.log"
file_handler = logging.FileHandler(log_path)
file_handler.setFormatter(logging.Formatter('%(message)s'))

activity_logger = logging.getLogger("victim_app_activity")
activity_logger.setLevel(logging.INFO)
activity_logger.addHandler(file_handler)
activity_logger.propagate = False

# --- Configuración de Seguridad y Autenticación ---
SECRET_KEY = "a_very_secret_key_for_a_vulnerable_app" # Clave secreta para firmar JWT
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Base de datos de usuarios en memoria (simulación)
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

# --- Funciones de Utilidad de Autenticación ---
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

# --- Inicialización de la App FastAPI ---
app = FastAPI(title="Victim App", description="A vulnerable application for security simulation.")

# --- Middleware para Logging de Peticiones ---
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    
    # Leer el cuerpo de la petición de forma segura
    raw_request_body = await request.body()
    try:
        # Intentar decodificar como texto para el log
        request_body_str = raw_request_body.decode('utf-8')
    except UnicodeDecodeError:
        request_body_str = f"Non-UTF8 body, length: {len(raw_request_body)}"

    response = await call_next(request)
    process_time = time.time() - start_time

    log_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": request.client.host,
        "request_method": request.method,
        "request_path": request.url.path,
        "request_query": str(request.query_params),
        "user_agent": request.headers.get("user-agent", "N/A"),
        "status_code": response.status_code,
        "processing_time_ms": round(process_time * 1000, 2),
        "raw_request_body": request_body_str,
    }
    
    # Escribir el log como una línea JSON en el archivo
    activity_logger.info(json.dumps(log_data))

    return response

# --- Endpoints de la API ---
@app.get("/", tags=["General"])
async def read_root():
    """Endpoint de bienvenida para simular tráfico benigno."""
    return {"message": "Welcome to the vulnerable application!"}

@app.post("/auth/login", tags=["Authentication"])
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Endpoint de autenticación. Acepta 'username' y 'password'.
    Vulnerable a ataques de enumeración de usuarios y fuerza bruta.
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
    """Endpoint protegido que devuelve la información del usuario actual."""
    return current_user

@app.get("/api/products", tags=["Products"])
async def get_products(token: str = Depends(oauth2_scheme)):
    """Endpoint protegido que lista productos. Requiere autenticación."""
    return [
        {"id": 1, "name": "Secure Widget", "price": 100.0},
        {"id": 2, "name": "Vulnerable Gadget", "price": 25.5},
    ]