#!/bin/sh

make clean;
rm -rf api;
sphinx-apidoc -MeT -o api ../
make html
