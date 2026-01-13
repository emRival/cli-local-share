from setuptools import setup, find_packages

setup(
    name="cli-local-share",
    version="2.0.0",
    packages=find_packages(),
    install_requires=[
        "rich",
        "qrcode",
        "paramiko",
        "sftpserver",
    ],
    entry_points={
        "console_scripts": [
            "sharecli=src.server:main",
            "sharecli-uninstall=src.utils:uninstall_tool",
        ],
    },
    python_requires=">=3.8",
)
