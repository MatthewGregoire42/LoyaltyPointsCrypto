FROM ubuntu:22.04

WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y curl build-essential
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release

# Copy the rest of the source code
COPY . .

# Set the startup command
CMD ["/usr/src/app/target/release/crypto"]
