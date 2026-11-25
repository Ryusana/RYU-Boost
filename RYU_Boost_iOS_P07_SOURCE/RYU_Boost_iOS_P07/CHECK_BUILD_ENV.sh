#!/usr/bin/env bash
set -eu
if [[ "$(uname -s)" != Darwin ]]; then
  echo 'BLOCKED: cần macOS + Xcode/iOS SDK. Không thể tạo IPA tại đây.' >&2
  exit 1
fi
for cmd in xcodebuild xcrun go xcodegen; do
  command -v "$cmd" >/dev/null || { echo "BLOCKED: thiếu $cmd" >&2; exit 1; }
done
xcodebuild -version
xcrun --sdk iphoneos --show-sdk-path
go version
xcodegen --version
echo 'Đã có công cụ cơ bản. Tiếp tục README để tạo project, tích hợp WireGuardGoBridge, ký Network Extension và build.'
