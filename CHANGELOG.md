# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] - 2023-04-07

### Added

- Add `containerd` support in the same way we support grabbing container
  metadata from docker. (#106)

- Build releases for arm64. (#107)

## [1.1.1] - 2022-01-24

### Fixed

- Fix `cgroup` support on non-amd64 architectures. (#96)

## [1.1.0] - 2022-01-24

### Added

- Added `cgroup` optional parser. When enabled, this will annotate audit
  events with the cgroup v2 root path. If running on an older system with only
  cgroup v1, this falls back to the pid cgroup path. (#95)

## [1.0.0] - 2020-06-18

### Added

- You can now run `go-audit -version` to check the build version.

[Unreleased]: https://github.com/slackhq/go-audit/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/slackhq/go-audit/releases/tag/v1.2.0
[1.1.1]: https://github.com/slackhq/go-audit/releases/tag/v1.1.1
[1.1.0]: https://github.com/slackhq/go-audit/releases/tag/v1.1.0
[1.0.0]: https://github.com/slackhq/go-audit/releases/tag/v1.0.0
