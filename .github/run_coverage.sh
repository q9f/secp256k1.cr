#!/usr/bin/env bash

rm -r .github/coverage/
crystal build .github/run_coverage.cr -D skip-integrations -o .github/run_coverage
kcov --clean --include-path=./src .github/coverage .github/run_coverage
