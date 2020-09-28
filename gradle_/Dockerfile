FROM gradle

ARG USER_ID
ARG GROUP_ID
ARG HOME_DIR

RUN if [ ${USER_ID:-0} -ne 0 ] && [ ${GROUP_ID:-0} -ne 0 ]; then \
    addgroup -g ${GROUP_ID} jenkins && \
    adduser -h $HOME_DIR -D -u ${USER_ID} -G jenkins jenkins \
;fi

USER jenkins