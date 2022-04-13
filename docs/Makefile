ALPINE_VERSION := 3.15
SVC := web-covertmark-com
COMMIT := $(shell git log -1 --pretty='%h')

# Minimal makefile for Sphinx documentation
SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
SPHINXPROJ    = CovertMark
SOURCEDIR     = .
BUILDDIR      = _build

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

.PHONY: help Makefile

# Docker
all: pull build push

build:
	@$(SPHINXBUILD) -M clean "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
	rm -rf api
	pandoc --from=markdown --to=rst --output=../README.rst ../README.md
	sphinx-apidoc -MeT -o api ../
	@$(SPHINXBUILD) -M html "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
	docker buildx build --platform linux/amd64 -t ${SVC} --build-arg ALPINE_VERSION=${ALPINE_VERSION} .

pull:
	docker pull alpine:${ALPINE_VERSION}

push:
	docker tag ${SVC}:latest icydoge/web:${SVC}-${COMMIT}
	docker push icydoge/web:${SVC}-${COMMIT}

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
