#!/bin/bash

kill -9 $(ps aux | grep scapy-sniffer.py | grep -v grep | awk '{ print $2 }')
kill -9 $(ps aux | grep ping | grep -v grep | awk '{ print $2 }')
