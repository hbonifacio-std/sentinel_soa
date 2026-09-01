import uuid
from dataclasses import dataclass, field


@dataclass(frozen=True)
class ObjectId:
    """
    Represents an immutable ObjectId with a unique string value.

    This class is designed to handle unique identifiers using UUIDv4 by default.
    The ObjectId is immutable and can be used in hashable contexts, such as keys
    in dictionaries or elements in sets.

    Attributes:
        value: A string representing the unique identifier of the ObjectId.

    Methods:
        from_string(cls, id_str: str) -> Self:
            Creates a new ObjectId instance from an existing string

        generate(cls) -> Self:
            Generates a new ObjectId with a UUIDv4 as its value

        __str__() -> str:
            Converts the ObjectId to its string representation

        __repr__() -> str:
            Returns a formal string representation of the ObjectId for debugging
    """

    value: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self):

        if not isinstance(self.value, str) or not self.value.strip():
            raise ValueError("the value must be a non-empty string")

        object.__setattr__(self, "value", self.value.strip())

    @classmethod
    def from_string(cls, id_str: str) -> "ObjectId":
        """
        Converts a string representation of an ObjectId into an ObjectId instance.

        This method is a class method used to create an ObjectId instance
        from its string representation.

        Parameters:
            id_str (str): The string representation of the ObjectId.

        Returns:
            ObjectId: A new instance of ObjectId created from the given string.
        """
        return cls(value=id_str)

    @classmethod
    def generate(cls) -> "ObjectId":
        """
        Generates a new instance of the ObjectId.

        This method acts as a factory method for creating new ObjectId instances.
        It initializes a new instance of the class using its constructor and
        returns it.

        @return: A new instance of ObjectId
        @rtype: ObjectId
        """
        return cls()

    def __str__(self) -> str:
        """
        Converts an object to its string representation.

        This method provides a readable string representation of an object's value.
        It is commonly used when printing or logging the object and ensures a
        meaningful output based on the object's value.

        Returns:
            str: The string representation of the object's value.
        """
        return self.value

    def __repr__(self) -> str:
        """
        Provides a string representation of the instance.

        The method returns a human-readable string representation of the object,
        which is primarily used for debugging purposes. The format of the returned
        string includes the class name and the value property.

        Returns:
            str: The string representation of the instance.
        """
        return f"ObjectId('{self.value}')"