#!/bin/bash

# run Python & Java processes
cd /app
nohup uvicorn python.main:app &>/dev/null &
nohup java -jar /app/java/spring-boot-application.jar &>/dev/null &
