# Installation Guide

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

## Step-by-Step Installation

1. **Clone or download the project**
   ```bash
   cd "path/to/cryptovault"
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

4. **Initialize the database**
   The database will be created automatically on first run.

5. **Run the application**
   ```bash
   python src/main.py
   ```

6. **Access the web interface**
   Open your browser and navigate to: `http://localhost:5000`

## Troubleshooting

### Import Errors
If you encounter import errors, make sure you're running from the project root directory:
```bash
python src/main.py
```

### Database Errors
If you see database-related errors, delete `cryptovault.db` and restart the application to recreate the database.

### Port Already in Use
If port 5000 is already in use, modify `src/main.py` to use a different port:
```python
app.run(debug=True, host='0.0.0.0', port=5001)
```

## Running Tests

```bash
# Install test dependencies (if not already installed)
pip install pytest pytest-cov

# Run all tests
pytest tests/

# Run with coverage report
pytest tests/ --cov=src --cov-report=html

# View coverage report
# Open htmlcov/index.html in your browser
```

