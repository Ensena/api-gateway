FROM frolvlad/alpine-glibc
WORKDIR /app
COPY configuration.json /app/configuration.json
COPY api  /app/
EXPOSE 8000
ENTRYPOINT ["/app/api"]