#!/bin/bash

ping "www.google.com" > /dev/null &
python scapy-sniffer.py &
