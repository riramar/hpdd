from setuptools import setup

setup(
    name="hpdd",
    version="0.1",
    description="Header Parsing Discrepancy Detector (hpdd): Detect HTTP header parsing discrepancies across proxies.",
    author="riramar",
    py_modules=["hpdd"],
    install_requires=[
        "requests",
    ],
    entry_points={
        "console_scripts": [
            "hpdd=hpdd:main"
        ]
    },
    python_requires=">=3.6",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)