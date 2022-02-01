FROM postgres:13

# These files could also be just mounted through volume from docker-compose, but postgres needs specific
# TLS cert and key file permissions to be set. Since it is not doable in Windows machine it must be done separately
# in Dockerfile. This also requires the given files to be in same build context as the Dockerfile.

COPY ./hydra-db.localhost.crt /etc/ssl/certs/server.crt
COPY ./hydra-db.localhost.key /etc/ssl/private/server.key

RUN chown postgres:postgres /etc/ssl/private/server.key
RUN chmod 600               /etc/ssl/private/server.key
