
from pydantic import Field
from pydantic_settings import BaseSettings

class DetectionSettings(BaseSettings):
    window_threshold_requests: int = Field(default=50, validation_alias="WINDOW_THRESHOLD_REQUESTS", gt=0)
    window_duration_seconds: int = Field(default=60, validation_alias="WINDOW_DURATION_SECONDS", gt=0)
    max_alerts_in_memory: int = Field(default=500, validation_alias="MAX_ALERTS_IN_MEMORY", gt=0, le=5000)
    bootstrap_on_startup: bool = Field(default=True, validation_alias="BOOTSTRAP_ON_STARTUP")