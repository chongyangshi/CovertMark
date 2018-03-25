#!/bin/sh

make clean; rm -rf source; sphinx-apidoc -o source ../; make html
