#!/bin/bash

# Iniciar la aplicación FastAPI con Uvicorn
exec python -m uvicorn core_orchestrator.main:app --host 0.0.0.0 --port 8000
