#!/bin/sh
make firewall
cat dump1.txt | ./firewall --print --file rules1.fw