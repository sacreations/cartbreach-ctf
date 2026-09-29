FROM python:3.12-alpine
RUN apk add --no-cache git
WORKDIR /var/git
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 3001
CMD ["/entrypoint.sh"]
