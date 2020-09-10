FROM maven:3-alpine

ARG USER_ID
ARG GROUP_ID

RUN if [ ${USER_ID:-0} -ne 0 ] && [ ${GROUP_ID:-0} -ne 0 ]; then \
    addgroup -g ${GROUP_ID} jenkins && \
    adduser -h $HOME -D -u ${USER_ID} -G jenkins jenkins \
;fi

USER jenkins