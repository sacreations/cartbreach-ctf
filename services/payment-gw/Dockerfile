FROM python:3.12-alpine
WORKDIR /app
RUN pip install --no-cache-dir flask
COPY . .
RUN addgroup -S payment && adduser -S payment -G payment
USER payment
EXPOSE 5000
CMD ["python", "app.py"]
