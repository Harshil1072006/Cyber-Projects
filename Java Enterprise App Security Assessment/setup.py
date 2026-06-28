from setuptools import setup, find_packages

setup(
    name="java_security_assessment",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "pyyaml",
        "jinja2",
        "weasyprint",
        "pydantic",
        "semgrep",
        "click",
        "rich"
    ],
    entry_points={
        "console_scripts": [
            "java-scan=java_security_assessment.cli:main",
        ],
    },
)
