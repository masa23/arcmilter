#!/bin/sh
set -eu

# 単体テストと結合テストの別プロセスを同じcoverpkg・atomicモードで計測する。
cd "$(dirname "$0")/.."
output_dir=${1:-coverage}
mkdir -p "$output_dir"
output_dir=$(cd "$output_dir" && pwd)
run_dir=$(mktemp -d "$output_dir/raw.XXXXXX")
mkdir -p "$run_dir/test" "$run_dir/process" "$run_dir/unit" "$run_dir/integration" "$run_dir/combined"

ARCMILTER_TEST_COVERDIR="$run_dir/process" \
  go test -count=1 -timeout=120s -covermode=atomic -coverpkg=./... ./... \
    -args "-test.gocoverdir=$run_dir/test"

# 異なるテストバイナリと実行ファイルの同じ関数を重複計上しない。
go tool covdata merge -pcombine -i="$run_dir/test" -o="$run_dir/unit"
go tool covdata merge -pcombine -i="$run_dir/process" -o="$run_dir/integration"
go tool covdata merge -pcombine -i="$run_dir/unit,$run_dir/integration" -o="$run_dir/combined"

go tool covdata textfmt -i="$run_dir/unit" -o="$output_dir/unit.out"
go tool covdata textfmt -i="$run_dir/integration" -o="$output_dir/integration.out"
go tool covdata textfmt -i="$run_dir/combined" -o="$output_dir/coverage.out"
go tool cover -func="$output_dir/unit.out" > "$output_dir/unit.txt"
go tool cover -func="$output_dir/integration.out" > "$output_dir/integration.txt"
go tool cover -func="$output_dir/coverage.out" > "$output_dir/coverage.txt"
go tool cover -html="$output_dir/coverage.out" -o="$output_dir/coverage.html"
cat "$output_dir/coverage.txt"
