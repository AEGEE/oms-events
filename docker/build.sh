#!/bin/bash

#docker login

docker build -t omsevents -f Dockerfile.dev .
docker tag omsevents aegee/omsevents:dev
docker push aegee/omsevents:dev