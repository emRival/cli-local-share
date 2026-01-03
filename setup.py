from setuptools import setup, find_packages

setup(
    name="cli-local-share",
    version="2.0.0",
    packages=find_packages(),
    install_requires=[
        "rich",
        "qrcode"
    ],
    entry_points={
        "console_scripts": [
            "sharecli=src.server:main",
        ],
    },
    python_requires=">=3.8",
)
