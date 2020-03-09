FROM python:3.7-alpine

USER root

RUN rm -rf /var/cache/apk/* && \
    rm -rf /tmp/*

RUN apk update && apk upgrade

RUN apk add --no-cache --virtual .build-deps \
        gcc \
        build-base \
        linux-headers \
        ca-certificates \
	mariadb-dev \
        python3-dev \
        libffi-dev \
        libressl-dev \
        git
RUN apk add -U --no-cache \
	libxslt-dev \
        bash


COPY report-tool /report-tool

WORKDIR /report-tool

RUN pip install --upgrade
RUN pip install -U setuptools
RUN pip install pymysql mysqlclient
RUN pip install --no-cache-dir -r /report-tool/requirements.txt

EXPOSE 5000

ENTRYPOINT [ "python" ]

CMD [ "fedsize_run.py" ]




