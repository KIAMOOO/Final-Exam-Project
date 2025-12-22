# Installation Guide

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Email service configured (Mailjet SMTP, local service, or custom)

## Step-by-Step Installation

1. **Clone or download the project**
   ```bash
   cd "path/to/Final-Exam-Project/Cryptography"
   ```

2. **Create a virtual environment (recommended)**
   ```bash
   python -m venv venv
   
   # On Windows:
   venv\Scripts\activate
   
   # On Linux/Mac:
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   - Copy `.env.example` to `.env`
   - Edit `.env` with your configuration:
   ```bash
   # Email Service (choose one):
   
   # Option 1: Mailjet SMTP (recommended)
   SMTP_SERVER=in-v3.mailjet.com
   SMTP_PORT=587
   SMTP_USERNAME=<your_mailjet_api_key>
   SMTP_PASSWORD=<your_mailjet_api_secret>
   FROM_EMAIL=<your_email@domain.com>
   
   # Option 2: Local Email Service (for development)
   USE_LOCAL_EMAIL=true
   
   # Flask settings
   FLASK_ENV=development
   SECRET_KEY=your-secret-key-here
   ```

5. **Initialize the database**
   The database will be created automatically on first run when you start the application.

6. **Run the application**
   ```bash
   python src/main.py
   ```

7. **Access the web interface**
   Open your browser and navigate to: `http://localhost:5000`

## Troubleshooting

### Import Errors
If you encounter import errors, make sure you're running from the project root directory:
```bash
cd /path/to/Final-Exam-Project/Cryptography
python src/main.py
```

### Database Errors
If you see database-related errors, delete `instance/cryptovault.db` and restart the application to recreate the database:
```bash
rm instance/cryptovault.db
python src/main.py
```

### Port Already in Use
If port 5000 is already in use, modify `src/main.py` to use a different port:
```python
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
```

### Email Service Issues
- **SMTP Authentication Failed**: Verify API key/secret are correct and enabled
- **Connection Refused**: Check internet connection and firewall settings
- **Email Not Arriving**: Check recipient address and spam folder

## Running Tests

```bash
# Install test dependencies (if not already installed)
pip install pytest pytest-cov

# Run all tests
pytest tests/

# Run specific test file
pytest tests/test_auth.py

# Run with coverage report
pytest tests/ --cov=src --cov-report=html

# View coverage report
# Open htmlcov/index.html in your browser
```

## Project Structure

```
Cryptography/
├── src/
│   ├── auth/                    # Authentication & authorization
│   │   ├── registration.py
│   │   ├── login.py
│   │   ├── totp.py
│   │   ├── email_service.py
│   │   ├── smtp_email_service.py
│   │   └── models.py
│   ├── crypto/                  # Cryptographic algorithms
│   │   ├── sha256.py
│   │   ├── rsa.py
│   │   ├── classical.py
│   │   └── aes_expansion.py
│   ├── files/                   # File encryption module
│   │   └── file_encryption.py
│   ├── messaging/               # Secure messaging
│   │   └── messaging.py
│   ├── blockchain/              # Audit trail
│   │   ├── blockchain.py
│   │   └── merkle.py
│   ├── web/                     # Flask web application
│   │   ├── app.py
│   │   ├── static/
│   │   └── templates/
│   ├── main.py
│   └── cryptovault.py           # Main API
├── tests/                       # Test suite
│   ├── test_auth.py
│   ├── test_crypto.py
│   ├── test_blockchain.py
│   └── __init__.py
├── email_logs/                  # Local email service logs
├── encrypted_files/             # Encrypted file storage
├── uploads/                     # File upload directory
├── requirements.txt
├── INSTALL.md
├── QUICKSTART.md
└── README.md
```

## Step 6: Verify Installation

### Test SMTP Connection
```bash
python test_smtp.py
```

Expected output:
```
✅ All tests passed! SMTP is working correctly.
```

---

## Step 7: Run Application

```bash
python src/web/app.py
```

Application will start at: **http://localhost:5000**

---

## Development Setup

### Running in Debug Mode

Already enabled in `.env` (`FLASK_ENV=development`)

### Running Tests

```bash
# Test email service
python test_smtp.py

# Run pytest (if configured)
pytest tests/
```

### Folder Structure After Installation

```
Final-Exam-Project-main/
└── Cryptography/
    ├── .env                              # Configuration
    ├── requirements.txt                  # Dependencies
    ├── src/
    │   ├── auth/
    │   │   ├── smtp_email_service.py    # Email service
    │   │   ├── models.py
    │   │   ├── login.py
    │   │   ├── registration.py
    │   │   └── ...
    │   ├── web/
    │   │   ├── app.py                   # Flask app
    │   │   ├── static/
    │   │   └── templates/
    │   ├── crypto/
    │   ├── blockchain/
    │   ├── files/
    │   └── messaging/
    ├── tests/
    ├── email_logs/                       # Email log files
    ├── uploads/                          # Uploaded files
    ├── cryptovault.db                    # SQLite database
    ├── test_smtp.py                      # Email tests
    └── email_service_factory.py          # Service factory
```

---

## Troubleshooting Installation

### "No module named 'flask'"
```bash
# Ensure you're in the correct directory and virtual environment is activated
pip install -r requirements.txt
```

### "SMTP Authentication failed" during test
1. Verify API key and secret are correct
2. Check that SMTP_USERNAME = API Key (not email)
3. Check that SMTP_PASSWORD = API Secret

### "Connection refused"
1. Check internet connection
2. Verify SMTP_SERVER = in-v3.mailjet.com
3. Verify SMTP_PORT = 587

### Database errors
```bash
# Reset database
rm cryptovault.db

# Reinitialize
python src/web/app.py
```

---

## Production Deployment

### Using Gunicorn

```bash
pip install gunicorn

gunicorn --bind 0.0.0.0:5000 \
  --workers 4 \
  --timeout 120 \
  src.web.app:app
```

### Using Docker

```dockerfile
FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Set environment variables (use your values)
ENV FLASK_ENV=production
ENV SMTP_SERVER=in-v3.mailjet.com
ENV SMTP_PORT=587
ENV SMTP_USERNAME=${SMTP_USERNAME}
ENV SMTP_PASSWORD=${SMTP_PASSWORD}
ENV FROM_EMAIL=${FROM_EMAIL}
ENV SECRET_KEY=${SECRET_KEY}

# Run application
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "src.web.app:app"]
```

Build and run:
```bash
docker build -t cryptovault .
docker run -p 5000:5000 \
  -e SMTP_USERNAME=your_key \
  -e SMTP_PASSWORD=your_secret \
  -e FROM_EMAIL=your_email \
  -e SECRET_KEY=your_secret \
  cryptovault
```

---

## Next Steps

1. ✅ Follow **QUICKSTART.md** for 5-minute setup
2. ✅ Review **README.md** for full documentation
3. ✅ Check **src/auth/smtp_email_service.py** for code details
4. ✅ Run `python test_smtp.py` to verify everything works

---

## Support

For issues:
1. Check that all environment variables are set
2. Run `python test_smtp.py` to verify SMTP
3. Review Flask logs for errors
4. Check `.env` file format

---

**Installation Complete!** 🎉

Now run:
```bash
python src/web/app.py
```

And visit http://localhost:5000
