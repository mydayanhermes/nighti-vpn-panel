FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN echo "Build: $(date)"
EXPOSE 8000
CMD sh -c "gunicorn app:app --bind 0.0.0.0:${PORT:-8000} --workers 1 --threads 8 --timeout 120"
