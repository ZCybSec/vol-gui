# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""Volatility 3 framework."""
# Check the python version to ensure it's suitable
import glob
import sys
import zipfile
import importlib
import inspect
import logging
import os
import traceback
import functools
import warnings
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple, Type, TypeVar

from volatility3.framework import constants, exceptions, interfaces
from volatility3.framework.configuration import requirements

if (
    sys.version_info.major != constants.REQUIRED_PYTHON_VERSION[0]
    or sys.version_info.minor < constants.REQUIRED_PYTHON_VERSION[1]
    or (
        sys.version_info.minor == constants.REQUIRED_PYTHON_VERSION[1]
        and sys.version_info.micro < constants.REQUIRED_PYTHON_VERSION[2]
    )
):
    raise RuntimeError(
        f"Volatility framework requires python version {'.'.join(str(x) for x in constants.REQUIRED_PYTHON_VERSION)} or greater"
    )

# ##
#
# SemVer version scheme
#
# Increment the:
#
#     MAJOR version when you make incompatible API changes,
#     MINOR version when you add functionality in a backwards compatible manner, and
#     PATCH version when you make backwards compatible bug fixes.


def interface_version() -> Tuple[int, int, int]:
    """Provides the so version number of the library."""
    return constants.VERSION_MAJOR, constants.VERSION_MINOR, constants.VERSION_PATCH


vollog = logging.getLogger(__name__)


def require_interface_version(*args) -> None:
    """Checks the required version of a plugin."""
    if len(args):
        if args[0] != interface_version()[0]:
            raise RuntimeError(
                f"Framework interface version {interface_version()[0]} is incompatible with required version {args[0]}"
            )
        if len(args) > 1:
            if args[1] > interface_version()[1]:
                raise RuntimeError(
                    "Framework interface version {} is an older revision than the required version {}".format(
                        ".".join(str(x) for x in interface_version()[0:2]),
                        ".".join(str(x) for x in args[0:2]),
                    )
                )


class Deprecation:
    """Deprecation related methods."""

    @staticmethod
    def deprecated_method(
        replacement: Callable,
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

                deprecation_msg = f"Method \"{deprecated_func.__module__ + '.' + deprecated_func.__qualname__}\" is deprecated, use \"{replacement.__module__ + '.' + replacement.__qualname__}\" instead. {additional_information}"
                warnings.warn(deprecation_msg, FutureWarning)
                # Return the wrapped function with its original arguments
                return deprecated_func(*args, **kwargs)

            return wrapper

        return decorator


class NonInheritable:
    def __init__(self, value: Any, cls: Type) -> None:
        self.default_value = value
        self.cls = cls

    def __get__(self, obj: Any, get_type: Type = Optional[None]) -> Any:
        if type is self.cls:
            if hasattr(self.default_value, "__get__"):
                return self.default_value.__get__(obj, get_type)
            return self.default_value
        raise AttributeError


def hide_from_subclasses(cls: Type) -> Type:
    cls.hidden = NonInheritable(True, cls)
    return cls


T = TypeVar("T")


def class_subclasses(cls: Type[T]) -> Generator[Type[T], None, None]:
    """Returns all the (recursive) subclasses of a given class."""
    if not inspect.isclass(cls):
        raise TypeError(f"class_subclasses parameter not a valid class: {cls}")
    for clazz in cls.__subclasses__():
        # The typing system is not clever enough to realize that clazz has a hidden attr after the hasattr check
        if not hasattr(clazz, "hidden") or not clazz.hidden:  # type: ignore
            yield clazz
        yield from class_subclasses(clazz)


def import_files(base_module, ignore_errors: bool = False) -> List[str]:
    """Imports all plugins present under plugins module namespace."""
    failures = []
    if not isinstance(base_module.__path__, list):
        raise TypeError("[base_module].__path__ must be a list of paths")
    vollog.log(
        constants.LOGLEVEL_VVVV,
        f"Importing from the following paths: {', '.join(base_module.__path__)}",
    )
    for path in base_module.__path__:
        for root, _, files in os.walk(path, followlinks=True):
            # TODO: Figure out how to import pycache files
            if root.endswith("__pycache__"):
                continue
            for filename in files:
                if zipfile.is_zipfile(os.path.join(root, filename)):
                    # Use the root to add this to the module path, and sub-traverse the files
                    new_module = base_module
                    premodules = root[len(path) + len(os.path.sep) :].replace(
                        os.path.sep, "."
                    )
                    for component in premodules.split("."):
                        if component:
                            try:
                                new_module = getattr(new_module, component)
                            except AttributeError:
                                failures += [new_module + "." + component]
                    new_module.__path__ = [
                        os.path.join(root, filename)
                    ] + new_module.__path__
                    for ziproot, zipfiles in _zipwalk(os.path.join(root, filename)):
                        for zfile in zipfiles:
                            if _filter_files(zfile):
                                submodule = zfile[: zfile.rfind(".")].replace(
                                    os.path.sep, "."
                                )
                                failures += import_file(
                                    new_module.__name__ + "." + submodule,
                                    os.path.join(path, ziproot, zfile),
                                )
                else:
                    if _filter_files(filename):
                        modpath = os.path.join(
                            root[len(path) + len(os.path.sep) :],
                            filename[: filename.rfind(".")],
                        )
                        submodule = modpath.replace(os.path.sep, ".")
                        failures += import_file(
                            base_module.__name__ + "." + submodule,
                            os.path.join(root, filename),
                            ignore_errors,
                        )

    return failures


def _filter_files(filename: str):
    """Ensures that a filename traversed is an importable python file"""
    return (filename.endswith((".py", ".pyc"))) and not filename.startswith("__")


def import_file(module: str, path: str, ignore_errors: bool = False) -> List[str]:
    """Imports a python file based on an existing module, a submodule and a filepath for error messages

    Args
        module: Module name to be imported
        path: File to be imported from (used for error messages)

    Returns
        List of modules that may have failed to import

    """
    failures = []
    if module not in sys.modules:
        try:
            importlib.import_module(module)
        except ImportError as e:
            vollog.debug(
                "".join(
                    traceback.TracebackException.from_exception(e).format(chain=True)
                )
            )
            vollog.debug(f"Failed to import module {module} based on file: {path}")
            failures.append(module)
            if not ignore_errors:
                raise
    return failures


def _zipwalk(path: str):
    """Walks the contents of a zipfile just like os.walk"""
    zip_results = {}
    with zipfile.ZipFile(path) as archive:
        for file in archive.filelist:
            if not file.is_dir():
                dirlist = zip_results.get(os.path.dirname(file.filename), [])
                dirlist.append(os.path.basename(file.filename))
                zip_results[os.path.join(path, os.path.dirname(file.filename))] = (
                    dirlist
                )
    yield from zip_results.items()


def list_plugins() -> Dict[str, Type[interfaces.plugins.PluginInterface]]:
    plugin_list = {}
    for plugin in class_subclasses(interfaces.plugins.PluginInterface):
        plugin_name = plugin.__module__ + "." + plugin.__name__
        if plugin_name.startswith("volatility3.plugins."):
            plugin_name = plugin_name[len("volatility3.plugins.") :]
        plugin_list[plugin_name] = plugin
    return plugin_list


def clear_cache(complete=True):
    try:
        if complete:
            glob_pattern = "*.cache"
            for cache_filename in glob.glob(
                os.path.join(constants.CACHE_PATH, glob_pattern)
            ):
                os.unlink(cache_filename)
        os.unlink(os.path.join(constants.CACHE_PATH, constants.IDENTIFIERS_FILENAME))
    except FileNotFoundError:
        vollog.log(constants.LOGLEVEL_VVVV, "Attempting to clear a non-existant cache")
