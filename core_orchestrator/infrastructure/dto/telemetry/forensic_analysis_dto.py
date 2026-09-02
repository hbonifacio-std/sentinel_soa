"""Domain entities for forensic search and report generation."""

from datetime import datetime, timezone
from typing import Any, Optional, List

from pydantic import BaseModel, Field, ConfigDict


class ChatForensicQuestionDTO(BaseModel):
    """
    Data Transfer Object (DTO) for handling forensic analysis requests.

    This class represents the structure and constraints required for an API request
    to perform forensic analysis. It encapsulates all the required and optional
    fields, along with validation rules for each field, ensuring that input data
    meets the expected format and constraints.
    """

    query: str = Field(..., min_length=3, max_length=1000)
    source_id: Optional[str] = Field(default=None, min_length=1, max_length=100)
    client_id: str = Field(default=None, min_length=1, max_length=100)
    model_id: str = Field(
        default=None,
        description="ID of the model to use (from the models enabled for the tenant)"
    )
    session_id: Optional[str] = None


class ForensicHistoryQueryDTO(BaseModel):
    """
    Data Transfer Object (DTO) for handling forensic history query information.

    This class is used to encapsulate the query parameters for forensic history
    requests within the system. It ensures proper validation and structure
    of the input data, making it easier to manage and use throughout the
    application.

    Attributes:
        source_id: Optional[str]
            The unique identifier of the source. Must be a string with a length
            between 1 and 100 characters. Default is None.
        client_id: Optional[str]
            The unique identifier of the client. Must be a string with a length
            between 1 and 100 characters. Default is None.
        page: int
            The page number for paginated results. Must be an integer greater than
            or equal to 1. Default is 1.
        limit: int
            The maximum number of results per page. Must be an integer between 1
            and 100 (inclusive). Default is 10.
    """
    client_id: Optional[str] = Field(default=None, min_length=1, max_length=100)
    page: int = Field(default=1, ge=1)
    limit: int = Field(default=10, ge=1, le=100)

class ChatMessageDTO(BaseModel):
    """
    Represents a data transfer object for a chat message.

    This class is designed to encapsulate the necessary information for
    representing a single chat message in a structured format. The message
    includes details such as the role of the issuer, its textual content, the
    timestamp in UTC when the message was created, and any associated metadata
    for contextual or operational purposes.

    Attributes:
    role (str): Issuer role, which can either be 'user', 'assistant', or 'system'.
    content (str): Text content of the message.
    timestamp_utc (datetime): Timestamp indicating when the message was issued in UTC format.
    metadata (dict[str, Any]): Contextual metadata associated with the message, provided as key-value pairs.
    """
    model_config = ConfigDict(from_attributes=True)

    role: str = Field(..., description="Issuer role: 'user', 'assistant' or 'system'")
    content: str = Field(..., description="Text content of the message")
    timestamp: datetime = Field(default_factory=lambda :datetime.now(timezone.utc), description="Fecha y hora del mensaje en UTC")
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Contextual metadata associated with the message"
    )



class ForensicChatSessionDTO(BaseModel):
    """
    Represents a forensic chat session.

    This class serves as a data transfer object for managing and representing chat
    sessions in a forensic or analytical context. It encapsulates details like the
    session ID, client information, timestamps, message history, and the session's
    status. Additionally, it tracks key findings or indicators discovered during
    the session.

    Attributes:
        session_id: Optional unique session identifier, such as a UUID or ObjectId.
        client_id: Identifier corresponding to the customer/tenant associated
            with this session.
        created_at_utc: Timestamp denoting when the session was created (in UTC).
        updated_at_utc: Timestamp indicating the most recent update to the session
            (in UTC).
        messages: A list of conversation messages related to this session.
        is_active: Indicates whether the session is currently active.
        highlighted: A list of key findings or indicators accumulated during the
            session.
    """
    model_config = ConfigDict(from_attributes=True)
    session_id: Optional[str] = Field(
        default=None, description="Unique session identifier (UUID or ObjectId)"
    )
    client_id: str = Field(..., description="Customer/tenant identifier")
    created_at_utc: datetime = Field(..., description="Session creation date in UTC")
    updated_at_utc: datetime = Field(..., description="Date of last update in UTC")
    messages: List[ChatMessageDTO] = Field(
        default_factory=list, description="Conversation message history"
    )
    is_active: bool = Field(default=True, description="Current session status")
    highlighted: List[str] = Field(
        default_factory=list, description="Cumulative list of findings or key indicators"
    )




class ForensicHistoryResponseDTO(BaseModel):
    """Paginated forensic analysis history response."""

    info: dict[str, Any]
    results: list[ForensicChatSessionDTO]
