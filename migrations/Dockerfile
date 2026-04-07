# To force linux/amd64 architecture so it runs properly on GKE nodes,
# pass the platform flag during build instead: docker build --platform linux/amd64
FROM alpine:3.19

# Install curl
RUN apk add --no-cache curl

# Download the AMD64 (x86_64) version of goose
RUN curl -fsSL -o /usr/local/bin/goose https://github.com/pressly/goose/releases/latest/download/goose_linux_x86_64 \
    && chmod +x /usr/local/bin/goose

WORKDIR /migrations

# Copy the wrapper script and make it executable
COPY run-migrations.sh .
RUN chmod +x run-migrations.sh

# Copy the actual SQL migrations
COPY *.sql ./

# Set the wrapper script as the entrypoint
ENTRYPOINT ["/migrations/run-migrations.sh"]
CMD ["up"]
