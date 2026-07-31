
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings

class MCPSettings(BaseSettings):
    url:str = Field(validation_alias="MCP_SERVER_URL")
    api_key_mcp: SecretStr = Field(validation_alias="MCP_INTERNAL_TOKEN")
