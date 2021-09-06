#!/bin/sh
gcc crazy-client.c -o crazy-client -g
g++ crazy-server.cpp -o crazy-server -lpthread

