#!/bin/sh
# Shared toolchain discovery, sourced by the other scripts.
#
# Both of these used to be hardcoded — `/Applications/Xcode-beta.app` and
# `/opt/homebrew/bin/protoc` — which built on exactly one machine.

# A full Xcode is required: this target links SwiftUI and AppKit, which the
# Command Line Tools SDK does not carry. An explicit DEVELOPER_DIR always wins.
if [ -z "${DEVELOPER_DIR:-}" ]; then
  selected=$(xcode-select -p 2>/dev/null || true)
  case "$selected" in
    */Xcode*.app/Contents/Developer) DEVELOPER_DIR=$selected ;;
    *)
      for candidate in /Applications/Xcode.app/Contents/Developer \
                       /Applications/Xcode-beta.app/Contents/Developer; do
        if [ -d "$candidate" ]; then
          DEVELOPER_DIR=$candidate
          break
        fi
      done
      ;;
  esac
  export DEVELOPER_DIR
fi

if [ -z "${DEVELOPER_DIR:-}" ] || [ ! -d "$DEVELOPER_DIR" ]; then
  echo "No Xcode found. Install it, run 'sudo xcode-select -s /Applications/Xcode.app'," >&2
  echo "or set DEVELOPER_DIR yourself. The Command Line Tools SDK has no SwiftUI." >&2
  exit 1
fi

# The protobuf plugins take the compiler from PROTOC_PATH; they cannot search
# PATH themselves, so an unset value fails the build with a message that never
# mentions protoc.
#
# PATH alone is not enough to find it. A script phase inherits Xcode's
# environment, and Xcode launched from the Dock inherits launchd's PATH — which
# has none of the directories your shell profile adds, /opt/homebrew/bin above
# all. protoc is installed and `command -v` still comes back empty, so look
# where package managers actually put it before giving up.
if [ -z "${PROTOC_PATH:-}" ]; then
  PROTOC_PATH=$(command -v protoc || true)
fi

if [ -z "${PROTOC_PATH:-}" ]; then
  for candidate in /opt/homebrew/bin/protoc \
                   /usr/local/bin/protoc \
                   /opt/local/bin/protoc; do
    if [ -x "$candidate" ]; then
      PROTOC_PATH=$candidate
      break
    fi
  done
fi
export PROTOC_PATH

if [ -z "${PROTOC_PATH:-}" ] || [ ! -x "${PROTOC_PATH:-}" ]; then
  echo "protoc not found. Install it (brew install protobuf) or set PROTOC_PATH." >&2
  echo "If this is an Xcode build: Xcode does not inherit your shell's PATH," >&2
  echo "so protoc being on PATH in a terminal does not put it on Xcode's." >&2
  exit 1
fi

# Everything spawned from here — swift build, and the plugins it runs — gets the
# same directory, for the same reason.
protoc_dir=$(dirname -- "$PROTOC_PATH")
case ":$PATH:" in
  *":$protoc_dir:"*) ;;
  *) PATH="$protoc_dir:$PATH"; export PATH ;;
esac
