FROM docker.io/aquasec/trivy AS trivy

FROM alpine:3.12

RUN apk --no-cache add ca-certificates git rpm
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=trivy /contrib/*.tpl /contrib/

ENTRYPOINT ["/bin/sh", "-c"]