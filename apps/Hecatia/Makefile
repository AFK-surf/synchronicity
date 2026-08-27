SHELL := /bin/sh

.PHONY: build release run run-release test check audit design-audit snapshots probe check-proto clean

build:
	@Scripts/build-app.sh debug

release:
	@Scripts/build-app.sh release

run:
	@Scripts/run-app.sh debug

run-release:
	@Scripts/run-app.sh release

# The protocol contract, unit tests, then the two audits a unit test cannot do.
#
# `audit-coverage.sh` counts the registry against Sources/Hecatia/control.proto
# and says so in its own header: counting that file is counting the daemon
# *only while the two are identical*. They were not. The app shipped the v2
# proto and a "2" version header against a daemon whose interceptor rejects
# anything but v3 on every call, so it could not open a connection at all —
# and this recipe stayed green through the whole of it, because `check-proto`
# sat below as a target nothing invoked.
#
# Before compilation rather than after it, and fatal on drift: a coverage count
# or a generated client taken from a stale proto is not a weaker check, it is a
# wrong one that reports success. The end-to-end script also proves that a
# missing canonical monorepo proto and a deliberately drifted copy both fail.
test:
	@Scripts/test-proto-sync.sh
	@. Scripts/env.sh && swift test
	@Scripts/audit-coverage.sh
	@Scripts/design-audit.sh

# Everything `test` does, plus a release build.
#
# Worth its own target because it is the only thing that compiles the release
# configuration: the preview harnesses are `#if DEBUG`, and one of them had an
# extension sitting outside its own conditional — so `swift build -c release`
# had been failing while `make test` stayed green.
check: test
	@. Scripts/env.sh && swift build -c release

audit:
	@Scripts/audit-coverage.sh
	@Scripts/design-audit.sh

design-audit:
	@Scripts/design-audit.sh

# Drives the real window and reports PASS/FAIL for the things a screenshot
# cannot answer: whether the versions panel takes its width from the sidebar,
# whether the filter field takes and gives back the focus, what the right
# button offers where, and what a folder delete would actually name. Needs a
# running daemon. See Sources/Hecatia/Preview/UIProbe.swift.
#
# PROBE=all runs the read-only suites. The ones that change something are
# asked for by name and want a scratch daemon and a scratch shared folder
# (HECATIA_PROBE_SHARE): `upload` sends six files and deletes them again and
# then checks the background watch still works, `add` shares a folder that
# already has files in it, `external` writes one behind the app's back, and
# `connection` watches while you stop and start the daemon yourself.
# Through the app bundle, never through `.build/debug/Hecatia`.
#
# The bare SwiftPM executable has no Info.plist and no bundle identity, so
# macOS gives it a different appearance and a different activation story from
# the app a person actually runs — measured, the two do not even render the
# toolbar the same way. Four rounds of focus checks passed against the bare
# binary while the fault was plain in the bundled one.
probe:
	@Scripts/build-app.sh debug >/dev/null
	@HECATIA_PROBE=$${PROBE:-all} dist/Hecatia.app/Contents/MacOS/Hecatia 2>&1 \
		| grep -E "PANEL|SEARCH|FOCUS|FETCH|MENUS|DELETE|POLICY|EXTERNAL|UPLOAD|ADD|CONNECTION|^    - |^  \[" || true

# Renders every surface to build/snapshots so a visual change can be looked at.
# HECATIA_SNAPSHOT_APPEARANCE=dark on the app binary captures the real windows
# in dark mode; see Sources/Hecatia/Preview/WindowSnapshot.swift.
snapshots:
	@HECATIA_SNAPSHOT_DIR=$(PWD)/build/snapshots sh -c '. Scripts/env.sh && swift test --filter Snapshots' >/dev/null 2>&1 || true
	@Scripts/build-app.sh debug >/dev/null
	@HECATIA_WINDOW_SNAPSHOT_DIR=$(PWD)/build/snapshots dist/Hecatia.app/Contents/MacOS/Hecatia >/dev/null 2>&1 || true
	@echo "snapshots in build/snapshots"

check-proto:
	@Scripts/sync-proto.sh check

clean:
	rm -rf .build dist XcodeGenerated
