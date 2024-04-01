# go-template

<!-- TODO: @memes - update badges as needed -->
[![Go Reference](https://pkg.go.dev/badge/github.com/memes/go-template.svg)](https://pkg.go.dev/github.com/memes/go-template)
[![Go Report Card](https://goreportcard.com/badge/github.com/memes/go-template)](https://goreportcard.com/report/github.com/memes/go-template)
![GitHub release](https://img.shields.io/github/v/release/memes/go-template?sort=semver)
![Maintenance](https://img.shields.io/maintenance/yes/2024)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)

This repository contains common settings and actions that I tend to use in my
Go projects.

## Setup

> NOTE: TODOs are sprinkled in the files and can be used to find where changes
> may be necessary.

1. Use as a template when creating a new GitHub repo, or copy the contents into
   a bare-repo directory.

2. Update `.pre-commit-config.yml` to add/remove plugins as necessary.
3. Modify README.md and CONTRIBUTING.md, change LICENSE as needed.
4. Review GitHub PR and issue templates.
5. If pushing container(s) to Docker Hub, make these changes to repo settings:
   1. _Settings_ > _Secrets and Variables_ > _Actions_, and add `DOCKERHUB_USERNAME`
      and `DOCKERHUB_TOKEN` as _Repository Secret_.
6. If using `release-please` action, make these changes:
   1. In GitHub Settings:
      * _Settings_ > _Actions_ > _General_  > _Allow GitHub Actions to create and approve pull requests_ is checked
      * _Settings_ > _Secrets and Variables_ > _Actions_, and add `RELEASE_PLEASE_TOKEN` with PAT as a _Repository Secret_
   2. Modify [release-please action](.github/workflows/release-please.yml) to have the correct package and enable
   3. Remove [version.txt](version.txt)
7. Review and enable [go-lint](.github/workflows/go-lint.yml) and [go-release](.github/workflows/go-release.yml) actions
8. Remove all [CHANGELOG](CHANGELOG.md) entries.
9. Commit changes.
