FROM node:8

RUN mkdir -p /usr/app/src \
	&& mkdir -p /usr/app/media \
	&& mkdir -p /usr/app/scripts

COPY ./docker/bootstrap.sh /usr/app/scripts/bootstrap.sh
COPY ./ /usr/app/src

RUN chown -R node:node /usr/app

WORKDIR /usr/app/src

USER node

ENV NPM_CONFIG_PREFIX=/home/node/.npm-global
ENV PATH="/home/node/.npm-global/bin:${PATH}"

RUN npm install -g --loglevel warn supervisor \
    && npm cache clean --force


CMD sh /usr/app/scripts/bootstrap.sh \
    && supervisor  --watch "." --timestamp --extensions "js,json" lib/server.js

EXPOSE 8082
