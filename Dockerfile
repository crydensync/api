# The PostgreSQL migration runner and the SQLite driver this repo uses are
# both pure Go, so the whole thing cross-compiles with CGO_ENABLED=0. That
# is what makes the final image small and what makes the release binaries
# below buildable for five platforms from one runner.
FROM golang:1.25-alpine AS build

WORKDIR /src

# go.mod/go.sum first, so a source-only change does not re-download the
# module graph. This is the whole reason the layer exists.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# -trimpath keeps the build directory out of the binary; -s -w drop the
# symbol table and DWARF data. Together they are most of the size, and
# nothing here debugs a stripped binary by hand.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /api .

# alpine rather than scratch or distroless, for one concrete reason: this
# image has to be able to write a SQLite database to a mounted volume, and
# a distroless nonroot image cannot be handed a writable directory without
# a COPY --chown trick that is harder to read than it is worth. alpine
# also brings ca-certificates, which the OAuth providers, the webhook
# sender and the Anthropic API all need.
FROM alpine:3.20

# The CA bundle, and nothing else. No shell, no package manager beyond
# what alpine ships — anything that gets added here is attack surface in a
# container that only ever runs one binary.
RUN apk add --no-cache ca-certificates && \
    adduser -D -u 10001 -h /home/api api

COPY --from=build /api /usr/local/bin/api

# A SQLite deployment needs somewhere to put the database that is not the
# container's writable layer, or every `docker compose up --build` is a
# new database. /data is that place; a Postgres deployment ignores it.
RUN mkdir -p /data && chown api:api /data
VOLUME ["/data"]

USER api

# 8080 is config.Load's default for PORT, so an image run with no PORT set
# listens where this line says it does.
EXPOSE 8080

# Exec form, deliberately, and the reason is SIGTERM. Shell form
# (`CMD /usr/local/bin/api`) runs the binary as a child of /bin/sh, which
# means `docker stop` signals the shell and the binary — and its
# in-flight requests — never see it. That would undo the whole point of
# main.go's graceful shutdown, so this line is load-bearing rather than
# stylistic.
ENTRYPOINT ["/usr/local/bin/api"]
