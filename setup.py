"""
Setup script for building the frozen_memory C extension.

Usage:
    python setup.py build_ext --inplace

The C extension is optional. If it cannot be compiled, the package
falls back to the ctypes-based implementation automatically.
"""

import os

from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
import sys


class OptionalBuildExt(build_ext):
    """
    Build C extensions as optional.

    If compilation fails (e.g., no MSVC, no GCC), the build
    continues without the extension. The Python fallback
    (frozen_memory_fallback.py) handles this at runtime.
    """

    def build_extension(self, ext):
        try:
            super().build_extension(ext)
        except Exception as e:
            print(f"\n{'='*60}")
            print(f"WARNING: Could not compile C extension '{ext.name}'")
            print(f"Reason: {e}")
            print(f"The package will use the Python ctypes fallback instead.")
            print(f"OS-level memory protection is still active via ctypes.")
            print(f"{'='*60}\n")


frozen_memory_ext = Extension(
    "sovereign_shield.frozen_memory",
    sources=["sovereign_shield/frozen_memory.c"],
    language="c",
)

# Only add platform-specific libraries
if sys.platform == "win32":
    frozen_memory_ext.libraries = ["kernel32"]

# Building the extension makes the wheel platform-specific. Every previously
# published wheel was cp312-win_amd64, so the wheel was uninstallable on Linux
# and macOS and those users silently fell back to the sdist. The engine is pure
# stdlib and hardware_protection falls back to ctypes, so the release build
# sets SOVEREIGN_SHIELD_SKIP_EXT=1 to produce a portable py3-none-any wheel.
# The .c source still ships, so anyone can compile it locally with
# `python setup.py build_ext --inplace`.
_ext_modules = (
    [] if os.environ.get("SOVEREIGN_SHIELD_SKIP_EXT") == "1"
    else [frozen_memory_ext]
)

setup(
    ext_modules=_ext_modules,
    cmdclass={"build_ext": OptionalBuildExt},
)
