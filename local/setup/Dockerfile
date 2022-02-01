FROM alpine:3.14.2
RUN apk add --no-cache --upgrade grep curl

COPY *.sh /
COPY *.json /
ADD https://raw.githubusercontent.com/Eficode/wait-for/v2.2.2/wait-for /wait-for.sh
RUN chmod +x /*.sh

ENTRYPOINT ["/init.sh"]