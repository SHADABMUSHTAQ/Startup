# Base image
FROM python:3.10-slim

# Set working directory inside container
WORKDIR /code

# Copy dependency file
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create non-root user for security
RUN adduser --disabled-password --gecos '' appuser

# Copy your project into container
COPY ./app ./app
COPY ./agent/windows_agent.py ./agent/windows_agent.py
COPY worker.py .
COPY verify.py .

# Give non-root user ownership and pre-create writable dirs
RUN mkdir -p uploaded_files && chown -R appuser:appuser /code

# Switch to non-root user
USER appuser

# Expose FastAPI port
EXPOSE 8000

# Run FastAPI using uvicorn (your main.py path and app variable)
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
