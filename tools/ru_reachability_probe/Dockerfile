FROM python:3.12-slim
WORKDIR /app
COPY server.py .
ENV PROBE_LISTEN=0.0.0.0 PROBE_PORT=8099
EXPOSE 8099
CMD ["python3", "server.py"]
