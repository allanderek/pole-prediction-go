#!/bin/bash

BIN=pole-prediction-backend
export POLEPREDICTION_ENV=prod 
export POLEPREDICTION_SESSION=dfv89sdfgij534tnreu98dfvknjdfnkldvfiu9dvfiuodvfknm 

sqlc generate && 
templ generate && 
go build -o $BIN . &&

./$BIN
