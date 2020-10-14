FROM docker.io/aquasec/trivy AS trivy

FROM alpine:3.12

ARG USER_ID
ARG GROUP_ID
ARG HOME_DIR

RUN if [ ${USER_ID:-0} -ne 0 ] && [ ${GROUP_ID:-0} -ne 0 ]; then \
    addgroup -g ${GROUP_ID} jenkins && \
    adduser -h $HOME_DIR -D -u ${USER_ID} -G jenkins jenkins \
;fi

USER jenkins

RUN apk --no-cache add ca-certificates git rpm
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=trivy /contrib/*.tpl /contrib/
ENTRYPOINT ["/bin/sh", "-c"]