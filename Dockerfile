# Base image
FROM python:3.10-slim

# Set working directory inside container
WORKDIR /code

# Copy dependency file
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy your project into container
COPY ./app ./app

# Expose FastAPI port
EXPOSE 8000

# Run FastAPI using uvicorn (your main.py path and app variable)
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
