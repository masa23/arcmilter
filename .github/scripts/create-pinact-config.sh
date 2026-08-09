#!/usr/bin/env bash

set -euo pipefail

readonly output="${1:?output config path is required}"

if [[ ! -f .pinact.yaml || ! -r .pinact.yaml ]]; then
  echo ".pinact.yaml is required and must be readable" >&2
  exit 1
fi

if [[ "${output}" == ".pinact.yaml" ]]; then
  echo "refusing to overwrite .pinact.yaml" >&2
  exit 1
fi

if [[ -e "${output}" || -L "${output}" ]]; then
  echo "refusing to overwrite existing output: ${output}" >&2
  exit 1
fi

command -v jq >/dev/null
command -v iconv >/dev/null

git ls-files -z -- \
  ':(glob).github/workflows/*.yml' \
  ':(glob).github/workflows/*.yaml' \
  ':(glob)**/action.yml' \
  ':(glob)**/action.yaml' |
  while IFS= read -r -d '' file; do
    if ! printf '%s' "${file}" | iconv -f UTF-8 -t UTF-8 >/dev/null 2>&1; then
      printf 'pinact target path is not valid UTF-8: %q\n' "${file}" >&2
      exit 1
    fi

    pattern="${file//\\/\\\\}"
    pattern="${pattern//\*/\\*}"
    pattern="${pattern//\?/\\?}"
    pattern="${pattern//\[/\\[}"
    jq -Rn --arg path "${pattern}" '$path'
  done |
  jq -s '
    if length == 0 then
      error("no pinact target files found")
    else
      {
        version: 3,
        min_age: {},
        files: map({pattern: .})
      }
    end
  ' >"${output}"
