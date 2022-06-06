FROM oryd/hydra:feature-govsso

USER root

# Add postgres client for running psql scripts during database clean-up.
RUN apk add --no-cache --upgrade postgresql-client

ENTRYPOINT ["/etc/hydra-janitor/janitor.sh"]
