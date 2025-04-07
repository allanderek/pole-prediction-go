#!/bin/bash

BIN=./tmp/main
export POLEPREDICTION_ENV=dev 
export POLEPREDICTION_SESSION=dfv89sdfgij534tnreu98dfvknjdfnkldvfiu9dvfiuodvfknm

sqlc generate && 
templ generate && 
go build -o $BIN . &&
(pkill -f $BIN ; ./$BIN )
