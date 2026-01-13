"""Setup script for Ready for AI."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="ready-for-ai",
    version="0.2.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Prepare documents for AI by redacting PII with encrypted restoration",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/ready-for-ai",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "ready_for_ai.web": [
            "templates/*.html",
            "static/*.css",
            "static/*.js",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Legal Industry",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Text Processing :: General",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "ready-for-ai=ready_for_ai.cli:main",
        ],
    },
)
