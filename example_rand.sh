#!/bin/sh
make all
generator 1000 | ./firewall --print --file rules1.fw