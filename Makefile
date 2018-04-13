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

# Pantheon make targets
deps-circle:
	gem install package_cloud

build-rpm:
	bash scripts/build-rpm.sh
	rm -rf artifacts/go-audit

push-rpm:
	bash scripts/push-packagecloud.sh internal

push-dev-rpm:
	bash scripts/push-packagecloud.sh internal-staging

.PHONY: test test-cov-html bench bench-cpu bench-cpu-long bin
.DEFAULT_GOAL := bin
