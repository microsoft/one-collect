# Create a build container.
FROM rust:1.74-buster as build

# Copy the repo into the container.
ADD . /one-collect

# Build the cli.
WORKDIR /one-collect/cli
RUN cargo build --release

# Create a deployment container.
FROM ubuntu:latest as deployment

# Copy the built binary to the final container.
COPY --from=build \
    /one-collect/cli/target/release/one_collect_cli \
    /one-collect/one_collect_cli

# Run the cli debug command.
ENTRYPOINT ["/one-collect/one_collect_cli", "debug"]
