FROM gcr.io/distroless/static-debian12

COPY build/assam /assam

EXPOSE 8080
VOLUME ["/data"]

ENTRYPOINT ["/assam"]
