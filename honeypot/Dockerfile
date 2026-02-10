FROM python:3.11-slim

WORKDIR /app

COPY honeypot.py logger.py ./

# Create logs directory
RUN mkdir -p /app/logs

EXPOSE 22

CMD ["python", "-u", "honeypot.py"]
