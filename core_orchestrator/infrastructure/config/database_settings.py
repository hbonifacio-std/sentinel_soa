from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings


class MongoSettings(BaseSettings):
    host: str = Field(default="mongo", validation_alias="MONGO_HOST")
    port: int = Field(default=27017, validation_alias="MONGO_PORT", gt=0, le=65535)
    user: str = Field(default="", validation_alias="MONGO_USER")
    password: SecretStr = Field(default=SecretStr(""), validation_alias="MONGO_PASSWORD")

    telemetry_db_name: str = Field(default="sentinel_soa", validation_alias="MONGO_DB_NAME")
    auth_db_name: str = Field(default="auth", validation_alias="AUTH_MONGO_DB_NAME")
    rules_db_name: str = Field(default="heuristic", validation_alias="RULES_MONGO_DB_NAME")

    @property
    def connection_uri(self) -> str:
        """Constructs the Mongo Connection URI safely."""
        pass_val = self.password.get_secret_value()
        if self.user and pass_val:
            return f"mongodb://{self.user}:{pass_val}@{self.host}:{self.port}/{self.telemetry_db_name}?authSource=admin"
        return f"mongodb://{self.host}:{self.port}/{self.telemetry_db_name}"


class RedisSettings(BaseSettings):
    host: str = Field(default="redis", validation_alias="REDIS_HOST")
    port: int = Field(default=6379, validation_alias="REDIS_PORT", gt=0, le=65535)
    password: SecretStr | None = Field(default=None, validation_alias="REDIS_PASSWORD")

    telemetry_db: int = Field(default=0, validation_alias="REDIS_TELEMETRY_DB")
    auth_db: int = Field(default=1, validation_alias="REDIS_AUTH_DB")
    rules_db: int = Field(default=3, validation_alias="REDIS_RULES_DB")


class Neo4jSettings(BaseSettings):
    uri: str = Field(default="bolt://localhost:7687", validation_alias="NEO4J_URI")
    user: str = Field(default="neo4j", validation_alias="NEO4J_USER")
    password: SecretStr = Field(default=SecretStr(""), validation_alias="NEO4J_PASSWORD")
    database: str = Field(default="neo4j", validation_alias="NEO4J_DATABASE")