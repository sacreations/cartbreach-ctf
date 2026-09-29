FROM python:3.12-alpine

# Install bash, netcat, su-exec, cron daemon
RUN apk add --no-cache bash netcat-openbsd su-exec busybox-extras curl

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8000
CMD ["/entrypoint.sh"]
