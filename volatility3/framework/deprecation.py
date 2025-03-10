# This file is Copyright 2025 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

# This file contains the Deprecation class used to deprecate methods in an orderly manner

import warnings
import functools
import inspect

from typing import Callable, Tuple

from volatility3.framework import interfaces, exceptions
from volatility3.framework.configuration import requirements


def method_being_removed(message: str, removal_date: str):
    def decorator(deprecated_func):
        @functools.wraps(deprecated_func)
        def wrapper(*args, **kwargs):
            warnings.warn(
                f"This API ({deprecated_func.__module__}.{deprecated_func.__qualname__}) will be removed in the first release after {removal_date}. {message}",
                FutureWarning,
            )
            return deprecated_func(*args, **kwargs)

        return wrapper

    return decorator


def deprecated_method(
    replacement: Callable,
    removal_date: str,
    replacement_version: Tuple[int, int, int] = None,
    additional_information: str = "",
):
    """A decorator for marking functions as deprecated.

    Args:
        replacement: The replacement function overriding the deprecated API, in the form of a Callable (typically a method)
        replacement_version: The "replacement" base class version that the deprecated method expects before proxying to it. This implies that "replacement" is a method from a class that inherits from VersionableInterface.
        additional_information: Information appended at the end of the deprecation message
    """

    def decorator(deprecated_func):
        @functools.wraps(deprecated_func)
        def wrapper(*args, **kwargs):
            nonlocal replacement, replacement_version, additional_information
            # Prevent version mismatches between deprecated (proxy) methods and the ones they proxy
            if (
                replacement_version is not None
                and callable(replacement)
                and hasattr(replacement, "__self__")
            ):
                replacement_base_class = replacement.__self__

                # Verify that the base class inherits from VersionableInterface
                if inspect.isclass(replacement_base_class) and issubclass(
                    replacement_base_class,
                    interfaces.configuration.VersionableInterface,
                ):
                    # SemVer check
                    if not requirements.VersionRequirement.matches_required(
                        replacement_version, replacement_base_class.version
                    ):
                        raise exceptions.VersionMismatchException(
                            deprecated_func,
                            replacement_base_class,
                            replacement_version,
                            "This is a bug, the deprecated call needs to be removed and the caller needs to update their code to use the new method.",
                        )

            deprecation_msg = f"Method \"{deprecated_func.__module__ + '.' + deprecated_func.__qualname__}\" is deprecated and will be removed in the first release after {removal_date}, use \"{replacement.__module__ + '.' + replacement.__qualname__}\" instead. {additional_information}"
            warnings.warn(deprecation_msg, FutureWarning)
            # Return the wrapped function with its original arguments
            return deprecated_func(*args, **kwargs)

        return wrapper

    return decorator
