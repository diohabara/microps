#!/usr/bin/env bash
set -euo pipefail

find . -iname *.h -o -iname *.c | xargs clang-format -i -style=GNU

