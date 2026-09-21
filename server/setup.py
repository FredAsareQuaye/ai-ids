from setuptools import setup, find_packages

setup(
    name="siem-server",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "fastapi",
        "uvicorn",
        "python-dotenv",
        "requests",
        "pydantic",
        "websockets",
        "python-socketio",
    ],
)