FROM --platform=$BUILDPLATFORM golang:alpine AS builder

RUN apk add --no-cache make git

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG TARGETVARIANT=

ENV CGO_ENABLED=0
ENV GOOS=${TARGETOS}
ENV GOARCH=${TARGETARCH}
ENV GOMIPS=softfloat

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN mkdir -p /out

RUN if [ "${TARGETARCH}" = "arm" ] && [ -n "${TARGETVARIANT}" ]; then \
        export GOARM=$(echo ${TARGETVARIANT} | sed 's/v//'); \
    elif [ "${TARGETARCH}" = "arm" ]; then \
        export GOARM=5; \
    fi; \
    go build -ldflags="-s -w" -o /out/rshell ./cmds/rshell

RUN go build -ldflags="-s -w" -o /out/goaccess ./cmds/goaccess

FROM scratch
COPY --from=builder /out/rshell /rshell
COPY --from=builder /out/goaccess /goaccess
ENTRYPOINT ["/goaccess"]
