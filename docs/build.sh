#!/bin/sh

make clean;
rm -rf api;
pandoc --from=markdown --to=rst --output=../README.rst ../README.md
sphinx-apidoc -MeT -o api ../
make html
