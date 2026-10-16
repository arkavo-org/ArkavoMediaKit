#!/bin/sh
# Run the pinned reference reader against a Swift-generated disposable-key fixture.
set -eu
: "${ARKAVO_ENVELOPE_FIXTURE_DIR:?Set to the absolute directory holding envelope.tdf and test-dek.bin}"
test -f "$ARKAVO_ENVELOPE_FIXTURE_DIR/envelope.tdf"
test -f "$ARKAVO_ENVELOPE_FIXTURE_DIR/test-dek.bin"
script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
validation_directory=$(mktemp -d "${TMPDIR:-/tmp}/arkavo-opentdf-validation.XXXXXX")
trap 'rm -rf "$validation_directory"' EXIT HUP INT TERM
git clone --quiet https://github.com/opentdf/platform.git "$validation_directory/platform"
git -C "$validation_directory/platform" checkout --quiet 4d9e555b
cp "$script_directory/arkavo_envelope_external_test.go.template" "$validation_directory/platform/sdk/arkavo_envelope_external_test.go"
(cd "$validation_directory/platform/sdk" && go test -run '^TestArkavoExternalEnvelope$' -v)
