FROM ubuntu:22.04

WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y curl build-essential
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Copy and build the source code
COPY . .
RUN cargo build --release

# Set the startup command
CMD ["/usr/src/app/target/release/crypto"]
