#!/bin/sh
# Hook for misc/echo.curl: the exchange arrives as JSON on stdin.
# Exit 0 to pass; print JSON with extra assertions and captures.
input=$(cat)
case "$input" in
  *'"x-client":"curly-examples"'*)
    echo '{"assertions":[{"name":"server saw X-Client","passed":true}],"captures":{"echo_checked":"yes"}}'
    ;;
  *)
    echo "the echoed headers did not include X-Client" >&2
    exit 1
    ;;
esac
