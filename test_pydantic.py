from datetime import datetime, timezone
from pydantic import BaseModel, Field, ConfigDict
import uuid
import json

# Recreate the model like in the real code
class AnalysisActionEntry(BaseModel):
    comment: str
    created_at_utc: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        alias="created_at_utc"
    )

class AnalysisReportResponse(BaseModel):
    """Schema for analytics report rows shown in Alert Center."""
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid.uuid4()), alias="_id")
    source_id: str | None = None
    source_ip: str | None = None
    threat_level: str | None = None
    threat_score: float | int | None = None
    kill_chain_phase: str | None = None
    reviewed: bool = False
    resolved: bool = False
    actions: list[AnalysisActionEntry] | list[dict] = Field(default_factory=list)
    created_at_utc: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    resolved_at_utc: str | None = None

# Test with by_alias=True (current code)
test_data = {
    "source_ip": "192.168.1.1",
    "threat_level": "HIGH",
    "source_id": "test-src-1"
}

report = AnalysisReportResponse.model_validate(test_data)

# Try dumping with by_alias=True (current implementation)
print("=== BY_ALIAS=TRUE (CURRENT) ===")
dumped_by_alias = report.model_dump(by_alias=True)
print(f"Type of dumped data: {type(dumped_by_alias)}")
print(f"Keys: {list(dumped_by_alias.keys())}")
print(f"_id value type: {type(dumped_by_alias['_id'])}")
print(f"_id value: {dumped_by_alias['_id']}")
try:
    json.dumps(dumped_by_alias, default=str)
    print("Can be JSON serialized: True")
except Exception as e:
    print(f"JSON serialization error: {e}")
print()

# Try dumping with mode="json" + by_alias=True (better approach)
print("=== MODE=JSON + BY_ALIAS=TRUE (BETTER) ===")
dumped_json_alias = report.model_dump(mode="json", by_alias=True)
print(f"Type of dumped data: {type(dumped_json_alias)}")
print(f"Keys: {list(dumped_json_alias.keys())}")
print(f"_id value type: {type(dumped_json_alias['_id'])}")
print(f"_id value: {dumped_json_alias['_id']}")
try:
    json.dumps(dumped_json_alias)
    print("Can be JSON serialized: True")
except Exception as e:
    print(f"JSON serialization error: {e}")

print("\n=== DIFFERENCE ===")
print(f"Same results? {dumped_by_alias == dumped_json_alias}")
