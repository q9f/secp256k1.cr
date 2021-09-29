#!/usr/bin/env bash

crystal build .github/run_coverage.cr -D skip-integrations -o .github/run_coverage
kcov --clean --include-path=./src .github/coverage .github/run_coverage
find .github/coverage -type f -name '*.js' -delete
find .github/coverage -type f -name '*.htm' -delete
find .github/coverage -type f -name '*.html' -delete
find .github/coverage -type f -name '*.css' -delete
find .github/coverage -type f -name '*.png' -delete
find .github/coverage -type f -name '*.so' -delete
