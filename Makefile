bin:
	govendor sync
	go build

test:
	govendor sync
	go test -v
	go test -v ./pkg/*

test-cov-html:
	go test -coverprofile=coverage.out
	go tool cover -html=coverage.out

bench:
	go test -bench=.

bench-cpu:
	go test -bench=. -benchtime=5s -cpuprofile=cpu.pprof
	go tool pprof go-audit.test cpu.pprof

bench-cpu-long:
	go test -bench=. -benchtime=60s -cpuprofile=cpu.pprof
	go tool pprof go-audit.test cpu.pprof

release: ## run a release. Should only be run from CI
release: VERSION=$(shell autotag -n)
release: LDFLAGS="-X github.com/pantheon-systems/go-audit/cmd.version=$(VERSION)+$(shell git rev-parse --short HEAD)"
release:
	github-release release -u pantheon-systems -r go-aduit -t $(VERSION) --draft -d "$(shell cat .circleci/release.template)"
	sha256sum go-audit > sha256sums.txt
	github-release upload -u pantheon-systems -r go-audit -n go-audit  -f go-audit -t $(VERSION)
	github-release upload -u pantheon-systems -r go-audit -n sha256sums.txt -f sha256sums.txt -t $(VERSION)

deps-release: # install tools needed for release, conditionally
ifneq ("$(wildcard Dockerfile))","")
	go get -u github.com/aktau/github-release
endif
	go get -u github.com/pantheon-systems/autotag/autotag

.PHONY: test test-cov-html bench bench-cpu bench-cpu-long bin release
.DEFAULT_GOAL := bin
