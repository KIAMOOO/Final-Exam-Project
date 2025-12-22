from setuptools import setup, find_packages

setup(
    name="cryptovault",
    version="1.0.0",
    description="Comprehensive cryptographic toolkit for secure communications and file encryption",
    author="CryptoVault Team",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "flask>=3.0.0",
        "flask-sqlalchemy>=3.1.1",
        "cryptography>=41.0.7",
        "pyotp>=2.9.0",
        "qrcode>=7.4.2",
        "Pillow>=10.1.0",
        "argon2-cffi>=23.1.0",
        "bcrypt>=4.1.1",
        "werkzeug>=3.0.1",
        "python-dotenv>=1.0.0",
    ],
    python_requires=">=3.8",
)

