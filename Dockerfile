FROM ubuntu:jammy AS base
LABEL Description="Dev environment"
ENV HOME /root
ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-c"]
COPY . /usr/src/app
RUN apt-get -y update && apt-get install -y
RUN apt-get install wget curl unzip git make sudo mono-complete -y

# Install Node.js and npm
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    npm install -g npm@latest

# .NET 9.0 install
WORKDIR /tmp
RUN wget https://dot.net/v1/dotnet-install.sh && chmod +x dotnet-install.sh && ./dotnet-install.sh -c 9.0
ENV PATH="$PATH:/root/.dotnet"

#Container runtime
FROM base AS build
WORKDIR /usr/src/app
RUN make clean environment
