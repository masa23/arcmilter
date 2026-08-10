#!/usr/bin/env ruby
# frozen_string_literal: true

require "open3"
require "pathname"
require "set"
require "yaml"

CONFIG_PATH = ".github/dependabot.yml"
WORKFLOW_DIRECTORY = ".github/workflows"

def fail_check(message)
  warn message
  exit 1
end

def normalize_directory(directory)
  # Match Dependabot::Job::SourceDefinition's path normalization.
  normalized = Pathname.new(directory).cleanpath.to_s
  normalized = "/#{normalized}" unless normalized.start_with?("/")
  relative = normalized.delete_prefix("/")
  if relative.split("/").include?("..")
    fail_check("Dependabot directory must stay within the repository: #{directory.inspect}")
  end

  normalized
end

def glob?(directory)
  directory.include?("*") || directory.include?("?") ||
    (directory.include?("[") && directory.include?("]"))
end

def covered_directories(entries)
  entries.each_with_object(Set.new) do |(pattern, allow_glob), covered|
    directory = normalize_directory(pattern)
    if directory == "/"
      covered << "."
      covered << WORKFLOW_DIRECTORY
      next
    end

    relative = directory.delete_prefix("/")
    matches = allow_glob && glob?(directory) ? Dir.glob(relative, File::FNM_DOTMATCH) : [relative]
    matches.select { |path| File.directory?(path) }.each do |path|
      canonical = Pathname.new(path).cleanpath.to_s
      covered << canonical
      # Dependabot's file fetcher also cleans "/." to "/" and then scans workflows.
      covered << WORKFLOW_DIRECTORY if canonical == "."
    end
  end
end

def dependabot_directory_entries
  config = YAML.safe_load_file(CONFIG_PATH, aliases: false)
  updates = config.is_a?(Hash) ? config["updates"] : nil
  fail_check("#{CONFIG_PATH} must contain an updates list") unless updates.is_a?(Array)

  definitions = updates.select do |update|
    update.is_a?(Hash) && update["package-ecosystem"] == "github-actions" &&
      [nil, "main"].include?(update["target-branch"])
  end
  fail_check("#{CONFIG_PATH} must configure github-actions updates for main") if definitions.empty?

  definitions.flat_map do |definition|
    if definition.key?("exclude-paths") && definition["exclude-paths"] != []
      fail_check("github-actions updates must not exclude manifest paths")
    end

    has_directory = definition.key?("directory")
    has_directories = definition.key?("directories")
    unless has_directory ^ has_directories
      fail_check("github-actions updates must define exactly one of directory or directories")
    end

    directories = has_directories ? definition["directories"] : [definition["directory"]]
    unless directories.is_a?(Array) && !directories.empty? &&
           directories.all? { |directory| directory.is_a?(String) && !directory.empty? }
      fail_check("github-actions directory entries must be non-empty strings")
    end
    directories.map { |directory| [directory, has_directories] }
  end
rescue Psych::Exception, SystemCallError => e
  fail_check("failed to read #{CONFIG_PATH}: #{e.message}")
end

stdout, stderr, status = Open3.capture3(
  "git", "ls-files", "-z", "--",
  ":(glob).github/workflows/*.yml",
  ":(glob).github/workflows/*.yaml",
  ":(glob)**/action.yml",
  ":(glob)**/action.yaml"
)
fail_check("git ls-files failed: #{stderr.strip}") unless status.success?

required_directories = stdout.b.split("\0").each_with_object(Set.new) do |raw_path, required|
  path = raw_path.force_encoding(Encoding::UTF_8)
  fail_check("GitHub Actions path is not valid UTF-8: #{path.dump}") unless path.valid_encoding?

  required << File.dirname(path)
end
fail_check("no GitHub Actions files were found") if required_directories.empty?

missing = required_directories - covered_directories(dependabot_directory_entries)
unless missing.empty?
  fail_check(
    "Dependabot does not cover GitHub Actions in: #{missing.to_a.sort.map(&:dump).join(', ')}. " \
    "Add the directories to the github-actions update configuration."
  )
end
