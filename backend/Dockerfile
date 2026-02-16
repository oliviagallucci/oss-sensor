FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir "uvicorn[standard]" httpx
COPY . .
RUN pip install -e .
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["uvicorn", "oss_sensor.main:app", "--host", "0.0.0.0", "--port", "8000"]
