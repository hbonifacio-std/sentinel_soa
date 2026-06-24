#!/usr/bin/env python
"""
🛠️ Gestor de Proveedores LLM - Herramienta de Administración

Este script es una HERRAMIENTA AUXILIAR para cambiar entre proveedores LLM.

⚠️  IMPORTANTE:
    • Este script NO se llama automáticamente en el flujo
    • El flujo automático lee .env → core_orchestrator → factory
    • Este script solo MODIFICA .env para cambiar el proveedor
    • Después de cambiar, se REQUIERE REINICIAR los servicios

Uso:
    python switch_llm_provider.py [proveedor]
    
Ejemplos:
    python switch_llm_provider.py openai      # Cambiar a OpenAI
    python switch_llm_provider.py groq        # Cambiar a GROQ
    python switch_llm_provider.py                     # Modo interactivo
"""

import sys
import os
from pathlib import Path

VALID_PROVIDERS = ['ollama', 'gemini', 'openai', 'groq']

PROVIDER_INFO = {
    'ollama': {
        'model': 'mistral (local)',
        'speed': '⚡ Rápido',
        'cost': '💰 Gratis',
        'quality': '⭐ Media',
        'descrip': 'LLM local sin costo'
    },
    'gemini': {
        'model': 'gemini-3.5-flash',
        'speed': '⚡⚡ Muy rápido',
        'cost': '💰 Bajo',
        'quality': '⭐⭐⭐⭐ Excelente',
        'descrip': 'Google Gemini (actual)'
    },
    'openai': {
        'model': 'gpt-4o-mini',
        'speed': '⚡⚡ Muy rápido',
        'cost': '💰💰 Moderado',
        'quality': '⭐⭐⭐⭐⭐ Excelente',
        'descrip': 'OpenAI (NEW)'
    },
    'groq': {
        'model': 'mixtral-8x7b-32768',
        'speed': '⚡⚡⚡ Ultra rápido',
        'cost': '💰 Gratis',
        'quality': '⭐⭐⭐⭐ Muy bueno',
        'descrip': 'GROQ (NEW - Ultra rápido)'
    }
}

def get_current_provider():
    """Lee el proveedor LLM actual del archivo .env"""
    env_file = Path(".env")
    if not env_file.exists():
        return None

    with open(env_file, "r") as f:
        for line in f:
            if line.startswith("LLM_PROVIDER="):
                return line.split("=")[1].strip()
    return None

def change_provider(new_provider: str) -> bool:
    """
    Cambia el proveedor LLM en el archivo .env

    Args:
        new_provider: Uno de 'ollama', 'gemini', 'openai', 'groq'
        
    Returns:
        bool: True si cambió exitosamente, False si erro
    """
    new_provider = new_provider.lower().strip()
    
    if new_provider not in VALID_PROVIDERS:
        print(f"❌ Proveedor inválido: '{new_provider}'")
        print(f"   Valores válidos: {', '.join(VALID_PROVIDERS)}")
        return False

    env_file = Path(".env")
    if not env_file.exists():
        print(f"❌ Archivo .env no encontrado en: {env_file.absolute()}")
        return False

    # Leer el contenido actual
    try:
        with open(env_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"❌ Error leyendo .env: {e}")
        return False

    # Actualizar la línea LLM_PROVIDER
    updated = False
    for i, line in enumerate(lines):
        if line.startswith("LLM_PROVIDER="):
            old_provider = line.split("=")[1].strip()
            lines[i] = f"LLM_PROVIDER={new_provider}\n"
            updated = True
            break

    if not updated:
        print(f"❌ No se encontró 'LLM_PROVIDER=' en .env")
        return False

    # Escribir de vuelta
    try:
        with open(env_file, "w", encoding="utf-8") as f:
            f.writelines(lines)
        print(f"✅ Proveedor cambiado exitosamente!")
        print(f"   Anterior: {old_provider}")
        print(f"   Nuevo:    {new_provider}")
        print(f"\n⚠️  RECORDAR: Se requiere reiniciar los servicios:")
        print(f"   docker-compose restart")
        print(f"   o")
        print(f"   python core_orchestrator/main.py")
        return True
    except Exception as e:
        print(f"❌ Error escribiendo .env: {e}")
        return False

def show_providers():
    """Muestra todos los proveedores disponibles"""
    print("\n📋 Proveedores LLM Disponibles:\n")
    
    current = get_current_provider()
    
    for i, provider in enumerate(VALID_PROVIDERS, 1):
        info = PROVIDER_INFO[provider]
        marker = "👉" if provider == current else "  "
        
        print(f"{marker} [{i}] {provider.upper()}")
        print(f"    Descripción: {info['descrip']}")
        print(f"    Modelo:      {info['model']}")
        print(f"    Velocidad:   {info['speed']}")
        print(f"    Costo:       {info['cost']}")
        print(f"    Calidad:     {info['quality']}")
        if provider == current:
            print(f"    ← ACTUAL")
        print()

def interactive_menu():
    """Menú interactivo para cambiar proveedores"""
    current = get_current_provider()
    
    print("\n" + "="*60)
    print("🛠️  GESTOR DE PROVEEDORES LLM")
    print("="*60)
    print(f"\n📍 Proveedor actual: {current.upper() if current else 'No configurado'}\n")
    
    show_providers()
    
    print("-"*60)
    print("Selecciona una opción:")
    print("  1-4  → Cambiar a ese proveedor")
    print("  l    → Listar todos")
    print("  q    → Salir")
    print("-"*60)
    
    while True:
        choice = input("\n¿Opción? ").strip().lower()
        
        if choice == 'q':
            print("Saliendo...")
            break
        elif choice == 'l':
            show_providers()
        elif choice in ['1', '2', '3', '4']:
            provider = VALID_PROVIDERS[int(choice) - 1]
            if provider != current:
                confirm = input(f"\n¿Cambiar a {provider.upper()}? (s/n) ").lower()
                if confirm == 's':
                    if change_provider(provider):
                        print("\n✅ Cambio completado")
                        current = provider
            else:
                print(f"⚠️  Ya estás usando {provider.upper()}")
        else:
            print("❌ Opción no válida")

if __name__ == "__main__":
    try:
        # Modo línea de comandos
        if len(sys.argv) > 1:
            provider = sys.argv[1]
            if not change_provider(provider):
                sys.exit(1)
        else:
            # Modo interactivo
            interactive_menu()
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Cancelado por usuario")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error inesperado: {e}")
        sys.exit(1)


