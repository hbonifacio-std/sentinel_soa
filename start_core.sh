#!/bin/bash

# Script de inicialización para el Core Orchestrator

# Este script ejecuta el servidor de aplicación Uvicorn, que sirve la API de FastAPI.
# - --host 0.0.0.0: Hace que el servidor escuche en todas las interfaces de red,
#   lo cual es necesario para que sea accesible desde fuera del contenedor Docker.
# - --port 8000: El puerto en el que se ejecutará la API, coincidiendo con el
#   puerto expuesto en el Dockerfile.

echo "🚀 Iniciando Core Orchestrator..."
uvicorn core_orchestrator.main:app --host 0.0.0.0 --port 8000