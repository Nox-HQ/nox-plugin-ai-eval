# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

- chore(deps): Go 1.26.5 and nox SDK v1.17.0 (#28)
- chore(security): nox remediation (deps + actions) (#27)
- ci: add nox-remediate caller (deps + action-pin remediation)
- ci: point the registry notice at where entries actually go (#26)
- ci: waive AI-040 on the adversarial evaluation corpus (#25)
- ci: add nox self-scan and changed-files PR gate (#24)


## [Unreleased]

## [0.2.0] - 2026-07-18

### Added

- Expanded adversarial corpus and coverage

  Reconciles work that had accumulated only in nox's `plugins/` directory,
  where a duplicate copy of this plugin lived. That copy has now been removed;
  this repository is the single source.

## [0.1.1]

Earlier releases predate this file. See the
[releases page](https://github.com/Nox-HQ/nox-plugin-ai-eval/releases) for their notes.
