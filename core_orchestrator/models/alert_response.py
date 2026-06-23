from pydantic import BaseModel, Field


class AlertResponseSchema(BaseModel):
    """Pydantic schema to enforce JSON output structure in the Gemini API."""

    threat_detected: bool = Field(
        ...,
        description="Boolean: true if there is evidence of scanning, attack, or malicious tools, false if 100% benign."
    )
    risk_level: str = Field(
        ...,
        description="Determined risk level. Allowed values: LOW, MEDIUM, HIGH, CRITICAL"
    )
    kill_chain_phase: str = Field(
        ...,
        description="Detected phase of the Cyber Kill Chain model or 'N/A' if benign."
    )
    report_summary: str = Field(
        ...,
        description="Detailed analytical report in Markdown format containing Diagnosis and Recommendations sections."
    )
