#!/bin/bash
(python solve.py; cat) | nc rop.syssec.dk 1337
