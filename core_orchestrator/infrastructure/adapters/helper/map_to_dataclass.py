import inspect
import json
import logging

from dataclasses import is_dataclass, asdict
from datetime import datetime, date
from typing import Type, Any, get_origin, get_args, get_type_hints, Optional, cast, TypeVar
from uuid import UUID



from core_orchestrator.domain.exceptions.mapper_exepcions import DeserializationException

logger = logging.getLogger(__name__)
T = TypeVar("T")

def _resolve_field_value(field_type: Any, value: Any) -> Any:
    """
    Resolves the value of a field by processing it based on its field type, handling
    cases such as lists or dictionaries containing dataclasses, and mapping them to
    the appropriate dataclass instances if necessary.

    Args:
        field_type (Any): The type of the field, which determines how the value
            is resolved
        value (Any): The value to be processed and resolved based on the field type

    Returns:
        Any: The resolved value after processing, matching the expected field type.
    """
    if value is None or not field_type:
        return value

    origin = get_origin(field_type)
    args = get_args(field_type)


    if origin is list and args and is_dataclass(args[0]):
        sub_cls = args[0]
        return [
            map_to_dataclass(sub_cls, item) if isinstance(item, dict) else item
            for item in value
        ]


    if origin is dict and len(args) == 2 and is_dataclass(args[1]):
        sub_cls = args[1]
        return {
            k: map_to_dataclass(sub_cls, v) if isinstance(v, dict) else v
            for k, v in value.items()
        }


    if is_dataclass(field_type) and isinstance(value, dict):
        return map_to_dataclass(field_type, value)

    return value


def _get_safe_type_hints(target_cls: Type[Any]) -> dict[str, Any]:
    """
    Retrieves type hints for a given class safely.

    This function attempts to fetch type hints from the provided class or object
    using `get_type_hints`. If an exception occurs during the process, it will
    return an empty dictionary instead of raising an error.

    Parameters:
    target_cls: Type[Any]
        The class or object for which to retrieve type hints.

    Returns:
    dict[str, Any]
        A dictionary mapping attribute names to their type hints. If an error
        occurs during retrieval, an empty dictionary is returned.
    """
    try:
        return get_type_hints(target_cls)
    except Exception as e:
        logger.exception("Failed to get type hints for %s", target_cls)
        logger.exception(e)
        return {}


def map_to_dataclass(target_cls: Type[T], data: dict[str, Any]) -> T:
    """
    Maps a dictionary to a dataclass of the specified type.

    This function attempts to map the keys and values from the input dictionary `data` to the
    fields of the specified dataclass `target_cls`. It ensures that only valid fields
    are included, and their types are resolved where possible. If the input is not a dictionary
    or the target class is not a dataclass, the function directly returns the input data without
    mapping. If an error occurs during the mapping process, a `DeserializationException` is raised.

    Parameters:
        target_cls (Type[T]): The target dataclass type to which the dictionary should be mapped
        data (dict[str, Any]): The input dictionary containing data to map to the dataclass

    Returns:
        T: An instance of the dataclass `target_cls` with its fields populated from the input dictionary.

    Raises:
        DeserializationException: If an error occurs during the mapping process, such as validation
        errors, incompatible data types, or other issues with populating the dataclass fields.
    """
    if not isinstance(data, dict) or not is_dataclass(target_cls):
        return data

    try:
        type_hints = _get_safe_type_hints(target_cls)
        valid_params = set(inspect.signature(target_cls).parameters.keys())

        converted_data = {
            k: _resolve_field_value(type_hints.get(k), v)
            for k, v in data.items()
            if k in valid_params
        }

        instantiator = cast(Any, target_cls)
        return instantiator(**converted_data)

    except Exception as exc:
        raise DeserializationException(
            target_cls_name=target_cls.__name__,
            reason=str(exc)
        ) from exc


def string_to_dataclass(target_cls: Type[T], raw_data: Optional[str]) -> Optional[T]:
    """
    Converts a JSON string into a dataclass instance of the specified type.

    This function takes a JSON string and deserializes it into a dictionary,
    then maps the dictionary to the provided dataclass type. If the input
    string is None or empty, it returns None.

    Parameters:
    target_cls: Type
        The dataclass type to which the JSON string should be mapped.
    raw_data: Optional[str]
        The JSON string to be converted into a dataclass. If None or empty,
        the function will return None.

    Returns:
    Optional[Type]
        An instance of the dataclass type specified by target_cls, populated
        with data from the JSON string. Returns None if raw_data is None or
        empty.
    """
    if not raw_data:
        return None

    data_dict = json.loads(raw_data)
    return map_to_dataclass(target_cls, data_dict)

def dataclass_to_string_json(data: T) -> Optional[str]:
    """
    Converts a dataclass instance to a JSON string representation with custom handling for
    non-standard types.

    The function serializes the provided dataclass instance into a JSON-formatted string
    using the built-in `json.dumps` method, while accommodating the serialization of
    datetime, date, and UUID objects. If the input is not a dataclass instance, it raises
    a ValueError.

    Parameters:
    data: T
        A dataclass instance to be serialized to JSON. It should be an instance of a
        Python dataclass object. Passing a non-dataclass instance will raise an error.

    Returns:
    Optional[str]
        A JSON string representation of the dataclass instance, or None if the serialization
        process fails.

    Raises:
    ValueError
        If the provided `data` is not a dataclass instance.

    TypeError
        If the data contains non-serializable objects that are neither datetime/date
        objects nor UUIDs.
    """
    if isinstance(data, type) or not is_dataclass(data):
        raise ValueError(f"Expected a dataclass instance, got {type(data).__name__}")

    def custom_encoder(obj: Any) -> Any:
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        if isinstance(obj, UUID):
            return str(obj)
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

    return json.dumps(asdict(data), default=custom_encoder)