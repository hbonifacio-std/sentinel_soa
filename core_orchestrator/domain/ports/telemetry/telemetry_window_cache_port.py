# core_orchestrator/domain/ports/telemetry_window_cache_port.py
from abc import ABC, abstractmethod
from typing import List, Any, Optional


class TelemetryWindowCachePort(ABC):
    """
    Interface for managing a sliding window mechanism.

    This abstract base class defines the interface for interacting with a sliding
    window mechanism. A sliding window enables the storage of time-sensitive,
    key-value pairs, allowing operations such as adding data, retrieving specific
    windows, and clearing them. Concrete implementations should define the specifics
    of data storage, retrieval, and window expiration. This is particularly useful
    in cases such as rate-limiting, telemetry collection, and stream-based
    analytics.

    Methods:
        add_to_window:
            Abstract method to add a key-value pair to a sliding window with a
            specified expiration time.
        add_multiple_to_window:
            Abstract method to add multiple values associated with a single key
            to the sliding window efficiently.
        get_active_window_keys:
            Abstract method to retrieve keys matching a specific pattern within
            the active sliding window store.
        get_window_size:
            Abstract method to fetch the number of events within a specific
            sliding window.
        get_and_clear_window:
            Abstract method to atomically retrieve all values from a window and
            delete it.
    """

    @abstractmethod
    async def add_to_window(self, key: str, value: Any, expire_seconds: int):
        """
        Abstract method to add a key-value pair to a sliding window mechanism.

        This method is designed to be implemented in subclasses, providing a way to
        store a key-value pair alongside an expiration time. The expiration time is
        used to determine the validity of the stored data in the sliding window.

        Parameters:
        key : str
            The key to identify the value being added to the sliding window.
        value : Any
            The value associated with the key to be added.
        expire_seconds : int
            The expiration time in seconds for the key-value pair in the sliding window.

        Raises:
        NotImplementedError
            This method must be implemented in subclasses.
        """
        raise NotImplementedError

    @abstractmethod
    async def add_multiple_to_window(self, key: str, values: List[Any], expire_seconds: int):
        """
        An abstract method for adding multiple values associated with a given key to a
        windowed data structure with a specified expiration time.

        This method should be implemented in subclasses to handle the addition of multiple
        values for a specified key into a data structure that manages a rolling window or
        expiration logic. The duration for which the data remains valid is defined by
        expire_seconds.

        Parameters:
            key: str
                The identifier for the values being added. It is used as the key within
                the windowed structure.
            values: List[Any]
                A list of values to associate with the specified key.
            expire_seconds: int
                The time in seconds after which the added values will expire or be
                removed from the windowed structure.

        Raises:
            NotImplementedError: Raised when this method is not implemented in a subclass.
        """
        raise NotImplementedError

    @abstractmethod
    async def force_expire_window(self, key: str, expire_seconds: int = 1) -> None:
        """
        Forces the TTL marker for a window to expire soon so the worker can process it.

        Implementations should update the auxiliary expiration key associated with the
        window without appending new data to the list itself.
        """
        raise NotImplementedError

    @abstractmethod
    async def get_active_window_keys(self, pattern: str) -> List[str]:
        """
        Provides an abstract method signature for retrieving active window keys with a specified
        pattern. This method is expected to be implemented by subclasses, and its implementation
        should return a list of keys for active windows that match the defined pattern.

        Arguments:
            pattern: str
                A string used to specify the search pattern for filtering the active
                window keys.

        Returns:
            List[str]
                A list containing the keys of active windows that match the given
                pattern.

        Raises:
            NotImplementedError
                This method must be implemented by subclasses and will raise this
                error if called directly without an implementation.
        """
        raise NotImplementedError

    @abstractmethod
    async def get_window_size(self, key: str) -> int:
        """
        An abstract method to retrieve the window size associated with a given key.

        The method is designed to be implemented by any subclass inheriting from the
        current abstract base class. It is expected to provide the logic for retrieving
        an integer value corresponding to a specific key.

        Parameters:
        key: str
            The string identifier for the window size to be retrieved.

        Returns:
        int
            The integer value representing the size of the window.

        Raises:
        NotImplementedError
            If the method is not overridden in a subclass.
        """
        raise NotImplementedError

    @abstractmethod
    async def get_and_clear_window(self, key: str) -> Optional[List[Any]]:
        """
        Provides an abstract method for retrieving and clearing a window of data
        associated with a specific key. This method must be implemented by
        subclasses to define custom behavior for handling such operations.

        Parameters:
            key: str
                The identifier for the specific data window to retrieve
                and clear.

        Returns:
            Optional[List[Any]]
                A list of data associated with the provided key, or None
                if no such data exists.

        Raises:
            NotImplementedError
                This error is raised when the method is not implemented
                in a subclass that inherits this abstract definition.
        """
        raise NotImplementedError


    @abstractmethod
    async def _handle_message(self, message: dict) -> None:
        """
        Abstract method to handle incoming messages.

        This method is meant to be implemented by subclasses to define
        the handling logic for messages provided in the form of a dictionary.
        Typically used in asynchronous workflows where message processing
        is required.

        Args:
            message (dict): The message payload to be processed, represented
                as a dictionary.

        Returns:
            None: This method does not return any value.

        Raises:
            NotImplementedError: If the method is called without being
                implemented in a subclass.
        """
        pass

    @abstractmethod
    async def start_listening(self) -> None:
        """
        An abstract method for initiating a listening process.

        This method is intended to be implemented by subclasses to define the logic for
        starting any asynchronous and possibly long-running listening operation.

        Raises:
            NotImplementedError: If the method is not implemented in a subclass.
        """
        pass
