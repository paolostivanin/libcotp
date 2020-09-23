#!/bin/bash

if [[ -z "$1" ]]; then
    echo "Usage: $0 <branch-name>"
    exit 1
fi

docker build -t "testme:Dockerfile" --build-arg BRANCH="$1" .
