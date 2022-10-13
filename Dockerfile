# syntax=docker/dockerfile:1

FROM python:3.7.15-alpine

WORKDIR /app

ARG SOPHOS_ID
ARG SOPHOS_SECRET
ARG ZABBIX_USER
ARG ZABBIX_PASS

ENV SOPHOS_ID=$SOPHOS_ID
ENV SOPHOS_SECRET=$SOPHOS_SECRET
ENV ZABBIX_USER=$ZABBIX_USER
ENV ZABBIX_PASS=$ZABBIX_PASS

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

COPY . .

ENTRYPOINT [ "python" ]

CMD ["app.py" ]
