from setuptools import setup, find_packages

setup(
    name="claude-guard",
    version="0.1.0",
    description="Claude Guard — AI-powered cloud infrastructure supervisor for Claude Code",
    author="Claude Guard",
    python_requires=">=3.9",
    packages=find_packages(exclude=["server", "server.*", "tests", "tests.*"]),
    py_modules=["claude_guard"],
    install_requires=[
        "anthropic>=0.39.0",
        "pyyaml>=6.0",
        "boto3>=1.34.0",
        "requests>=2.31.0",
    ],
    extras_require={
        "gcp": [
            "google-cloud-compute>=1.15.0",
            "google-cloud-container>=2.36.0",
            "google-cloud-storage>=2.14.0",
            "google-cloud-resource-manager>=1.11.0",
            "google-cloud-monitoring>=2.19.0",
            "google-cloud-logging>=3.9.0",
            "google-cloud-functions>=1.13.0",
            "google-cloud-run>=0.10.0",
            "google-cloud-iam>=2.12.0",
        ],
        "dev": ["pytest>=7.0"],
    },
    entry_points={
        "console_scripts": [
            "claude-guard=claude_guard:main",
        ],
    },
)
