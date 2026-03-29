import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="fido2client",
    version="0.10.5",
    author="origliante",
    author_email="please.visit.github@page.nowhere",
    description="WebAuthn API FIDO2 client",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/origliante/python-fido2-client",
    packages=setuptools.find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "fido2>=0.9.0",
        "cbor2>=5.0.0",
        "requests>=2.25.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Internet",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
