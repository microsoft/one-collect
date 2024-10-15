# Create a build container.
FROM rust:1.74-buster as build

# Copy the repo into the container.
ADD . /one-collect
RUN mkdir /perf_export

# Build the perf_export example.
WORKDIR /one-collect/one_collect
RUN cargo build --release --example perf_export

# Create a deployment container.
FROM ubuntu:latest as deployment
COPY --from=build \
    /one-collect/one_collect/target/release/examples/perf_export \
    /one-collect/perf_export

RUN mkdir /perf_export_data

ENTRYPOINT [ "/bin/bash", "-c", "/one-collect/perf_export /perf_export_data && ls /perf_export_data" ]