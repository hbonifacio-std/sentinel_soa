class LLMException(Exception):
    """
    Generic exception for errors related to LLM providers.
    Inherits from Exception and can be caught for general LLM error handling.
    """
    pass


class LLMConfigurationException(LLMException):
    """
    Raised when the configuration provided to an LLM provider is invalid or incomplete.
    Example: Missing model name, missing API key, or invalid endpoint URL.
    """
    pass


class LLMCommunicationException(LLMException):
    """
    Raised when network or API communication with the LLM provider fails.
    Example: Timeouts, HTTP errors, or unreachable local servers.
    """
    pass


class LLMResponseParseException(LLMException):
    """
    Raised when the LLM response cannot be parsed into the expected domain format.
    Example: Corrupted JSON or invalid schema in the model response.
    """
    pass


class LLMEmptyResponseException(LLMException):
    """
    Raised when the LLM returns an empty response or only whitespace.
    Example: The provider HTTP call succeeds, but the 'response' or 'content' field is empty.
    """
    pass


class LLMLimitExceededException(LLMException):
    """
    Raised when LLM usage boundaries or execution limits are breached.
    Example: Token limit/context window exceeded, rate limits (429), or response generation timeouts.
    """
    pass

