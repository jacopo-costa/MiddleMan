# syntax=docker/dockerfile:1

FROM python:alpine

WORKDIR /app

ARG SOPHOS_ID
ARG SOPHOS_SECRET
ARG TENANT_NAME
ARG ZABBIX_USER
ARG ZABBIX_PASS
ARG ZABBIX_HOSTNAME
ARG ZABBIX_PORT

ENV SOPHOS_ID=$SOPHOS_ID
ENV SOPHOS_SECRET=$SOPHOS_SECRET
ENV ZABBIX_USER=$ZABBIX_USER
ENV ZABBIX_PASS=$ZABBIX_PASS
ENV TENANT_NAME=$TENANT_NAME
ENV ZABBIX_HOSTNAME=$ZABBIX_HOSTNAME
ENV ZABBIX_PORT=$ZABBIX_PORT

COPY . .
RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT [ "python" ]

CMD ["app.py" ]
