FROM alpine:3.5

MAINTAINER Hong Minhee <hong.minhee@gmail.com>

RUN apk add --no-cache python3 ca-certificates
RUN apk add --no-cache py3-cryptography py3-paramiko py3-werkzeug py3-flask \
                       py3-libcloud
RUN update-ca-certificates
RUN mkdir -p /usr/local/bin/src/geofront

COPY . /usr/local/bin/src/geofront
RUN pip3 install /usr/local/bin/src/geofront


EXPOSE 8080
CMD if [[ ! -f /etc/geofront.cfg.py ]]; \
      then cp /usr/local/bin/src/geofront/docker.cfg.py /etc/geofront.cfg.py; \
    fi && \
    geofront-server --port 8080 \
                    --create-master-key \
                    $OPTIONS \
                    /etc/geofront.cfg.py
