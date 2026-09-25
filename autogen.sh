#!/bin/sh
# Regenerate the build system from a git checkout.
set -e
autoreconf --force --install --verbose
