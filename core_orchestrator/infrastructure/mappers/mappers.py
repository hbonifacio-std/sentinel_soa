
from dataclasses import asdict, is_dataclass, replace
from typing import TypeVar, Generic, Type, List, Any, Mapping, get_args, get_origin, Union, get_type_hints, Dict

from pydantic import BaseModel

from core_orchestrator.domain.entities.rule_engine import HeuristicRule, ValidationRules
from core_orchestrator.domain.entities.telemetry.forensic import ForensicChatSession
from core_orchestrator.domain.entities.telemetry.logs_event import LogEvent
from core_orchestrator.domain.entities.telemetry.reports import AnalysisReport
from core_orchestrator.domain.object_value.object_id import ObjectId
from core_orchestrator.infrastructure.adapters.mongodb.responses import PaginationMeta
from core_orchestrator.infrastructure.dto.responses import InfoPaginatedDTO, ResponsePaginatedDTO
from core_orchestrator.infrastructure.dto.rules_heuristics.rules_heuristics_dto import RuleResponseDTO
from core_orchestrator.infrastructure.dto.telemetry.analysis_report_dto import AnalysisReportResponseDTO
from core_orchestrator.infrastructure.dto.telemetry.forensic_analysis_dto import ForensicChatSessionDTO
from core_orchestrator.infrastructure.dto.telemetry.log_event_dto import LogEventDTO

T = TypeVar("T")
D = TypeVar("D", bound=BaseModel)

class GenericMapper(Generic[T, D]):
    def __init__(self, dataclass_cls: Type[T], dto_cls: Type[D]) -> None:
        self.dataclass_cls = dataclass_cls
        self.dto_cls = dto_cls

    def _sanitize_payload_for_dto(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitizes a dictionary payload by masking sensitive fields, recursively handling nested
        structures, and normalizing MongoDB ObjectId to string format. This ensures compatibility
        with data transfer objects (DTOs) and avoids exposing sensitive information.

        Parameters:
        payload: Dict[str, Any]
            The dictionary payload to be sanitized. It may contain nested structures.

        Returns:
        Dict[str, Any]
            A sanitized version of the input dictionary where sensitive fields are masked, and
            nested structures are appropriately managed.
        """
        if not isinstance(payload, dict):
            return payload

        # Set of keys or attributes containing sensitive information
        SENSITIVE_FIELDS = {
            "password",
            "password_hash",
            "secret",
            "secret_key",
            "api_key",
            "auth_token",
            "access_token",
            "authorization",
            "raw_headers",
            "cookie",
        }

        sanitized = {}

        for key, value in payload.items():
            # 1. Obfuscate sensitive fields
            if key.lower() in SENSITIVE_FIELDS:
                sanitized[key] = "******"

            # 2. Handling nested dictionaries (recursive)
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_payload_for_dto(value)

            # 3. Handling lists of dictionaries or complex elements
            elif isinstance(value, list):
                sanitized[key] = [
                    self._sanitize_payload_for_dto(item) if isinstance(item, dict)
                    else (str(item) if isinstance(item, ObjectId) else item)
                    for item in value
                ]

            # 4. Normalize ObjectId to string for DTO/JSON compatibility
            elif isinstance(value, ObjectId):
                sanitized[key] = str(value)

            else:
                sanitized[key] = value

        return sanitized

    def _resolve_type(self, field_type: Any, target_type: Type) -> bool:
        """
        Resolves whether a given field type matches a target type. This function checks if the
        field type is directly the same as the target type or, in cases where the field type is a
        Union, determines if any of its arguments match the target type.

        Args:
            field_type (Any): The actual type of the field being analyzed.
            target_type (Type): The type against which the field type is being compared.

        Returns:
            bool: True if the field type matches the target type, either directly or as part of a
            Union. False otherwise.
        """
        if field_type is target_type:
            return True
        origin = get_origin(field_type)
        if origin is Union:
            return any(
                self._resolve_type(arg, target_type)
                for arg in get_args(field_type)
            )
        return False

    def to_dataclass(self, dto: D) -> T:
        """
        Converts a Data Transfer Object (DTO) to a dataclass or a Pydantic model instance.

        This method facilitates the transformation of data from a DTO object into a target
        dataclass or Pydantic model while ensuring type coercion and handling nested
        structures if necessary.

        Args:
            dto (D): The Data Transfer Object instance that contains the source data.

        Returns:
            T: An instance of the target dataclass or Pydantic model containing the transformed
            data.

        Raises:
            ValueError: If the transformation process encounters inconsistencies with the
            field types or data structure.
            Other exceptions may be raised as appropriate for specific type coercions
            or nested transformations.
        """
        data = dto.model_dump()

        if hasattr(self.dataclass_cls, "__dataclass_fields__"):
            type_hints = get_type_hints(self.dataclass_cls)

            def _resolve_dataclass_type(field_type: Any):
                if isinstance(field_type, type) and is_dataclass(field_type):
                    return field_type
                origin = get_origin(field_type)
                if origin is Union:
                    for arg in get_args(field_type):
                        resolved = _resolve_dataclass_type(arg)
                        if resolved is not None:
                            return resolved
                return None

            def _coerce(field_type: Any, value: Any):
                if value is None:
                    return None

                #1. Explicit support for coercing str to ObjectId
                if self._resolve_type(field_type, ObjectId):
                    if isinstance(value, str):
                        return ObjectId.from_string(value)
                    if isinstance(value, ObjectId):
                        return value

                # 2. Coercion for nested dataclasses
                nested_type = _resolve_dataclass_type(field_type)
                if nested_type is not None and isinstance(value, Mapping):
                    nested_hints = get_type_hints(nested_type)
                    nested_payload = {}
                    for (
                        nested_name,
                        nested_def,
                    ) in nested_type.__dataclass_fields__.items():
                        if nested_name in value:
                            nested_payload[nested_name] = _coerce(
                                nested_hints.get(nested_name, nested_def.type),
                                value[nested_name],
                            )
                    return nested_type(**nested_payload)

                return value

            fields = self.dataclass_cls.__dataclass_fields__.keys()
            payload = {}
            for field_name in fields:
                if field_name in data:
                    payload[field_name] = _coerce(
                        type_hints.get(field_name), data[field_name]
                    )
            return self.dataclass_cls(**payload)

        if isinstance(self.dataclass_cls, type) and issubclass(
            self.dataclass_cls, BaseModel
        ):
            return self.dataclass_cls.model_validate(data)

        return self.dataclass_cls(**data)

    def to_dataclass_list(self, dtos: List[D]) -> List[T]:
        return [self.to_dataclass(dto) for dto in dtos]

    def to_dto(self, entity: T) -> D:
        """
        Converts an entity instance into a Data Transfer Object (DTO).

        This method takes an entity, checks its structure (dataclass, Pydantic model, or
        dictionary-like object), and extracts its data into a payload. The payload is then
        validated using the DTO class associated with this instance.

        Args:
            entity (T): The entity instance to be converted. It can be a dataclass,
            a Pydantic model, or an object with dictionary-like attributes.

        Returns:
            D: An instance of the DTO class validated with the extracted and processed
            payload.

        Raises:
            ValidationError: If the payload generated from the entity does not match
            the schema of the associated DTO class.
        """
        if hasattr(entity, "__dataclass_fields__"):
            payload = asdict(entity)
            # Cleanly flatten any ObjectId transformed by asdict into a {'value': '...'} dict
            payload = self._sanitize_payload_for_dto(payload)
        elif hasattr(entity, "model_dump"):
            payload = entity.model_dump()
        else:
            payload = dict(getattr(entity, "__dict__", {}))

        return self.dto_cls.model_validate(payload)

    def to_dto_list(self, entities: List[T]) -> List[D]:
        return [self.to_dto(entity) for entity in entities]

    def to_paginated_dto(
            self,
            entities: List[T],
            info_paginated: PaginationMeta,
            path: str
    ) -> ResponsePaginatedDTO[D]:
        """
        Converts a list of entities into a paginated response DTO.

        This method takes a list of entities, pagination metadata, and a base path,
        then constructs a paginated response DTO containing the entities converted to
        DTO format and additional pagination information such as total records, current
        page, next page, and previous page.

        Parameters:
            entities (List[T]): The list of entities to be converted into the DTO list
            info_paginated (PaginationMeta): The pagination metadata, including the
                total number of records, current page, and limit per page
            path (str): The base path used to construct the next and previous page links

        Returns:
            ResponsePaginatedDTO[D]: The DTO containing the paginated results and
            accompanying pagination information.
        """

        dto_list = self.to_dto_list(entities)
        skip = (info_paginated.page - 1) * info_paginated.limit
        next_page = f"{path}?page={info_paginated.page + 1}&limit={info_paginated.limit}" if (skip + info_paginated.limit) < info_paginated.total_records else None
        prev_page = f"{path}?page={info_paginated.page - 1}&limit={info_paginated.limit}" if info_paginated.page > 1 else None


        info = InfoPaginatedDTO(
            total_records=info_paginated.total_records,
            page=info_paginated.page,
            limit=info_paginated.limit,
            next_page=next_page,
            prev_page=prev_page
        )

        return ResponsePaginatedDTO(
            info=info,
            results=dto_list
        )

class AnalysisReportMapper(GenericMapper[AnalysisReport, AnalysisReportResponseDTO]):
    def __init__(self):
        super().__init__(dataclass_cls=AnalysisReport, dto_cls=AnalysisReportResponseDTO)

class LogEventMapper(GenericMapper[LogEvent, LogEventDTO]):
    def __init__(self):
        super().__init__(dataclass_cls=LogEvent, dto_cls=LogEventDTO)


class RuleMapper(GenericMapper[HeuristicRule, RuleResponseDTO]):
    def __init__(self):
        super().__init__(dataclass_cls=HeuristicRule, dto_cls=RuleResponseDTO)

    def to_dataclass(self, dto: BaseModel) -> HeuristicRule:
        rule = super().to_dataclass(dto)
        if rule.validation_rules is None:
            return replace(rule, validation_rules=ValidationRules())
        return rule

class ChatForensicMapper(GenericMapper[ForensicChatSession,ForensicChatSessionDTO]):
    def __init__(self):
        super().__init__(dataclass_cls=ForensicChatSession,dto_cls=ForensicChatSessionDTO)

analysis_report_mapper = AnalysisReportMapper()
log_event_mapper = LogEventMapper()
rule_mapper = RuleMapper()
chat_forensic_mapper = ChatForensicMapper()



