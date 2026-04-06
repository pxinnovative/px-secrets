"""
Setup script for PX Secrets.

PX Secrets is a single-file application — this setup.py exists
for metadata and to support `pip install .` for dependency resolution.
"""
from setuptools import setup

APP_NAME = "PX Secrets"
VERSION = "1.4.1"

setup(
    name="px-secrets",
    version=VERSION,
    description="Free & open-source local secrets manager — SOPS + AGE encrypted vault with GUI and CLI.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="PX Innovative Solutions Inc.",
    author_email="github@pxinnovative.com",
    url="https://github.com/pxinnovative/px-secrets",
    license="AGPL-3.0",
    py_modules=["px_secrets"],
    python_requires=">=3.9",
    install_requires=[
        "flask",
        "pyyaml",
    ],
    extras_require={
        "native": ["pywebview"],
    },
    entry_points={
        "console_scripts": [
            "px-secrets=px_secrets:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Web Environment",
        "Framework :: Flask",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Operating System :: MacOS",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
        "Topic :: Utilities",
    ],
    keywords="secrets manager sops age encryption vault local privacy",
)
