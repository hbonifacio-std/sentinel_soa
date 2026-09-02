from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional, Literal, List

from core_orchestrator.domain.object_value.object_id import ObjectId


@dataclass
class ForensicQuestion:
    """
    Represents a request to analyze forensic data.

    This class is used for constructing a request to perform a forensic
    data analysis by specifying relevant parameters such as client information,
    query details, and optional identifiers for source and model.

    Attributes:
      client_id (str): The unique identifier for the client making the request
      prompt_user (str): The query string describing what is to be analyzed or extracted
      source_id (Optional[str]): An optional identifier for the source of data that
        will be analyzed
      model_id (Optional[str]): An optional identifier for the model to be used
        during the forensic analysis
    """
    client_id: str
    prompt_user: str
    source_id: Optional[str] = None
    model_id: Optional[str] = None

@dataclass
class ChatMessage:
    role: Literal["user", "assistant", "system"]
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

@dataclass
class ForensicChatSession:
    client_id: str
    session_id: Optional[ObjectId] = None
    created_at_utc: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    updated_at_utc: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    messages: List[ChatMessage] = field(default_factory=list)
    is_active: bool = True

    highlighted: List[str] = field(default_factory=list)


    def get_list_messages_dict(self)->list[dict[str, str]]:
        return [
            {
                "role": msg.role,
                "content": msg.content
            }
            for msg in self.messages
        ]

    @classmethod
    def get_id_field_name(cls) -> str:
        """
        Returns the name of the identifier field for the session.

        This method checks if the session identifier field has an attribute named
        'name'. If the attribute exists, it returns the value of that attribute.
        Otherwise, it defaults to returning the string 'session_id'.

        Returns:
            str: The name of the session identifier field.
        """
        if hasattr(cls, "session_id"):
            return "session_id"
        return "id"

    def add_message(
            self,
            role: Literal["user", "assistant", "system"],
            content: str,
            metadata: Optional[dict[str, Any]] = None,
    ):
        """
        Adds a new message to the conversation and updates the timestamp.

        The method creates a `ChatMessage` object from the given parameters and appends
        it to the list of saved messages. Additionally, it updates the `updated_at_utc`
        attribute to the current UTC time to reflect when the messages were modified.

        Parameters:
            role (Literal["user", "assistant", "system"]): The role of the sender of the
            message. Must be one of "user", "assistant", or "system"
            content (str): The main textual content of the message
            metadata (Optional[dict[str, Any]]): Additional information about the
            message, stored as key-value pairs. Defaults to an empty dictionary if not
            provided.
        """
        self.messages.append(
            ChatMessage(
                role=role, content=content, metadata=metadata or {}
            )
        )
        self.updated_at_utc = datetime.now(timezone.utc)

    def add_highlight(self, item: str) -> None:
        """
        Adds a non-empty, stripped string to the list of highlighted items.

        Parameters:
        item (str): The string to be added to the highlighted list. It must not be empty or contain only
                    whitespace.

        Returns:
        None
        """
        if item and item.strip():
            self.highlighted.append(item.strip())

    def add_highlights(self, items: List[str]) -> None:
        """
        Adds highlights to the instance using the provided list of items.

        This method iterates through the given list of items and calls
        `add_highlight` for each item to add it as a highlight.

        Args:
            items (List[str]): A list of string items to be added as highlights.

        Returns:
            None
        """
        for item in items:
            self.add_highlight(item)