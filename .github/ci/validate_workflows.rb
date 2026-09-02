#!/usr/bin/env ruby
# frozen_string_literal: true

require "pathname"
require "yaml"

class WorkflowSecurityValidator
  EXTERNAL_ACTION = %r{\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[^@\s]+)?@[0-9a-fA-F]{40}\z}
  PINNED_CONTAINER_ACTION = %r{\Adocker://[^@\s]+@sha256:[0-9a-fA-F]{64}\z}
  PINNED_CONTAINER_IMAGE = %r{\A(?!docker://)[^@\s]+@sha256:[0-9a-fA-F]{64}\z}
  EXPRESSION = /\$\{\{/
  ALLOWED_GITHUB_PATHS = [
    "event.pull_request.number",
    "ref",
    "repository"
  ].freeze
  FORBIDDEN_CONTEXT = %r{
    \bsecrets\b
    |
    \bgithub\s*\.\s*token\b
  }ixm

  attr_reader :errors

  def initialize(root)
    @root = Pathname.new(root).realpath
    @errors = []
    @visited_local_actions = {}
    @yaml_cache = {}
    @workflows = []
    @validate_jobs = []
  end

  def run
    workflow_paths.each do |path|
      data = load_yaml(path, "workflow")
      next if data.nil?

      relative = display_path(path)
      unless data.is_a?(Hash)
        @errors << "workflow root must be a mapping: #{relative}"
        next
      end

      record = { path: path, relative: relative, data: data, jobs: [] }
      @workflows << record
      validate_workflow(record)
    end

    validate_required_check
    self
  end

  def success?
    @errors.empty?
  end

  def summary
    "#{@workflows.length} workflow(s) and #{@visited_local_actions.length} local action(s)"
  end

  private

  def workflow_paths
    Dir.glob(@root.join(".github", "workflows", "*.{yml,yaml}").to_s)
       .sort
       .map { |filename| Pathname.new(filename) }
  end

  def display_path(path)
    path.relative_path_from(@root).to_s
  rescue ArgumentError
    path.to_s
  end

  def load_yaml(path, kind)
    cache_key = path.expand_path.to_s
    return @yaml_cache[cache_key] if @yaml_cache.key?(cache_key)

    text = path.read
    stream = Psych.parse_stream(text, filename: path.to_s)
    if stream.children.length != 1
      @errors << "#{kind} YAML must contain exactly one document: #{display_path(path)}"
      return nil
    end

    check_duplicate_keys(stream, display_path(path))
    data = YAML.safe_load(
      text,
      permitted_classes: [],
      permitted_symbols: [],
      aliases: false,
      filename: path.to_s
    )
    @yaml_cache[cache_key] = data
    data
  rescue Psych::Exception, Errno::ENOENT, Errno::EACCES => e
    @errors << "invalid #{kind} YAML: #{display_path(path)}: #{e.message.lines.first.strip}"
    @yaml_cache[cache_key] = nil
    nil
  end

  def check_duplicate_keys(node, source, location = "root")
    if node.is_a?(Psych::Nodes::Mapping)
      seen = {}
      node.children.each_slice(2).with_index do |(key_node, value_node), index|
        unless key_node.is_a?(Psych::Nodes::Scalar)
          @errors << "complex YAML mapping keys are not permitted: #{source}: #{location}"
          check_duplicate_keys(key_node, source, "#{location}.key#{index}")
          check_duplicate_keys(value_node, source, "#{location}.value#{index}")
          next
        end

        key = key_node.value
        if seen.key?(key)
          @errors << "duplicate YAML mapping key: #{source}: #{location}.#{key}"
        else
          seen[key] = true
        end
        check_duplicate_keys(value_node, source, "#{location}.#{key}")
      end
    elsif node.respond_to?(:children) && node.children
      node.children.each_with_index do |child, index|
        check_duplicate_keys(child, source, "#{location}[#{index}]")
      end
    end
  end

  def scan_forbidden_contexts(node, source, location = "root")
    case node
    when Hash
      node.each do |key, value|
        scan_forbidden_contexts(key, source, "#{location}.key")
        scan_forbidden_contexts(value, source, "#{location}.#{key}")
      end
    when Array
      node.each_with_index { |value, index| scan_forbidden_contexts(value, source, "#{location}[#{index}]") }
    when String
      if FORBIDDEN_CONTEXT.match?(node)
        @errors << "credential context is not permitted: #{source}: #{location}"
      end
      scan_github_contexts(node, source, location)
    end
  end

  def scan_github_contexts(value, source, location)
    extract_expressions(value, source, location).each do |expression|
      expression = mask_quoted_literals(expression)
      cursor = 0
      while (context = /\bgithub\b/i.match(expression, cursor))
        tail = expression[context.end(0)..]
        path_match = /\A\s*((?:\.\s*[A-Za-z_][A-Za-z0-9_-]*)+)/.match(tail)
        unless path_match
          @errors << "whole, wildcard, or computed github context is not permitted: #{source}: #{location}"
          cursor = context.end(0)
          next
        end

        normalized_path = path_match[1].gsub(/\s+/, "").delete_prefix(".").downcase
        remainder = tail[path_match.end(0)..]
        dynamic_suffix = remainder&.match?(/\A\s*(?:\.|\[)/)
        unless ALLOWED_GITHUB_PATHS.include?(normalized_path) && !dynamic_suffix
          @errors << "github context path is not allowlisted: #{source}: #{location}"
        end
        cursor = context.end(0) + path_match.end(0)
      end
    end
  end

  def extract_expressions(value, source, location)
    expressions = []
    cursor = 0
    while (start_index = value.index("${{", cursor))
      index = start_index + 3
      quote = nil
      closed = false
      while index < value.length
        character = value[index]
        if quote
          if character == quote
            if value[index + 1] == quote
              index += 2
              next
            end
            quote = nil
          end
          index += 1
          next
        end

        if character == "'" || character == '"'
          quote = character
          index += 1
          next
        end
        if character == "}" && value[index + 1] == "}"
          expressions << value[(start_index + 3)...index]
          cursor = index + 2
          closed = true
          break
        end
        index += 1
      end

      unless closed
        @errors << "expression cannot be safely parsed: #{source}: #{location}"
        break
      end
    end
    expressions
  end

  def mask_quoted_literals(expression)
    result = expression.dup
    index = 0
    quote = nil
    while index < expression.length
      character = expression[index]
      if quote
        result[index] = " "
        if character == quote
          if expression[index + 1] == quote
            result[index + 1] = " " if index + 1 < result.length
            index += 2
            next
          end
          quote = nil
        end
        index += 1
        next
      end

      if character == "'" || character == '"'
        quote = character
        result[index] = " "
      end
      index += 1
    end
    result
  end

  def validate_workflow(record)
    data = record[:data]
    events = data.key?("on") ? data["on"] : data[true]
    event_names = event_names(events)
    if event_names.include?("pull_request_target")
      @errors << "pull_request_target is not permitted: #{record[:relative]}"
    end

    jobs = data["jobs"]
    unless jobs.is_a?(Hash)
      @errors << "workflow jobs must be a mapping: #{record[:relative]}"
      return
    end

    jobs.each do |job_id, job|
      location = "#{record[:relative]}: jobs.#{job_id}"
      unless job_id.is_a?(String) && job.is_a?(Hash)
        @errors << "workflow job must be a named mapping: #{location}"
        next
      end

      effective_name = effective_job_name(job_id, job, location)
      job_record = { workflow: record, id: job_id, job: job, effective_name: effective_name }
      record[:jobs] << job_record
      @validate_jobs << job_record if effective_name == "validate"

      scan_uses(job["uses"], "#{location}.uses", :workflow) if job.key?("uses")
      scan_steps(job["steps"], "#{location}.steps") if job.key?("steps")
    end
  end

  def event_names(events)
    case events
    when String
      [events]
    when Array
      events.map(&:to_s)
    when Hash
      events.keys.map(&:to_s)
    else
      []
    end
  end

  def effective_job_name(job_id, job, location)
    return job_id unless job.key?("name")

    name = job["name"]
    unless name.is_a?(String) && !EXPRESSION.match?(name)
      @errors << "job check name must be a static string: #{location}.name"
      return nil
    end
    name
  end

  def scan_steps(steps, location)
    unless steps.is_a?(Array)
      @errors << "steps must be a sequence: #{location}"
      return
    end

    steps.each_with_index do |step, index|
      next unless step.is_a?(Hash)
      next unless step.key?("uses")

      scan_uses(step["uses"], "#{location}[#{index}].uses", :action)
    end
  end

  def scan_uses(value, source, local_kind)
    unless value.is_a?(String)
      @errors << "uses must be a string: #{source}"
      return
    end

    if value.start_with?("./")
      if local_kind == :workflow
        validate_local_workflow_reference(value, source)
      else
        validate_local_action(value, source)
      end
      return
    end

    if value.start_with?("docker://")
      if local_kind == :workflow
        @errors << "a reusable workflow cannot be a container action: #{source}"
      elsif !PINNED_CONTAINER_ACTION.match?(value)
        @errors << "container action is not digest pinned: #{source}"
      end
      return
    end

    unless EXTERNAL_ACTION.match?(value)
      @errors << "external action or reusable workflow is not commit pinned: #{source}"
    end
  end

  def resolve_inside_root(relative, source)
    lexical = (@root + relative.delete_prefix("./")).cleanpath
    unless inside?(@root, lexical)
      @errors << "local reference escapes repository: #{source}"
      return nil
    end
    unless lexical.exist?
      @errors << "local reference does not exist: #{source}"
      return nil
    end

    resolved = lexical.realpath
    unless inside?(@root, resolved)
      @errors << "local reference resolves outside repository: #{source}"
      return nil
    end
    resolved
  rescue Errno::ENOENT, Errno::EACCES => e
    @errors << "cannot resolve local reference: #{source}: #{e.class}"
    nil
  end

  def inside?(parent, child)
    child.to_s == parent.to_s || child.to_s.start_with?(parent.to_s + File::SEPARATOR)
  end

  def validate_local_workflow_reference(value, source)
    target = resolve_inside_root(value, source)
    return if target.nil?

    workflow_root = @root.join(".github", "workflows")
    unless target.file? && inside?(workflow_root, target) && [".yml", ".yaml"].include?(target.extname.downcase)
      @errors << "local reusable workflow must be a YAML file in .github/workflows: #{source}"
    end
  end

  def validate_local_action(value, source)
    directory = resolve_inside_root(value, source)
    return if directory.nil?
    unless directory.directory?
      @errors << "local action reference must name a directory: #{source}"
      return
    end

    manifest = [directory + "action.yml", directory + "action.yaml"].find(&:file?)
    if manifest.nil?
      @errors << "local action manifest missing: #{source}"
      return
    end

    manifest = manifest.realpath
    return if @visited_local_actions[manifest.to_s]

    @visited_local_actions[manifest.to_s] = true
    data = load_yaml(manifest, "local action")
    return if data.nil?
    unless data.is_a?(Hash)
      @errors << "local action root must be a mapping: #{display_path(manifest)}"
      return
    end

    runs = data["runs"]
    unless runs.is_a?(Hash) && runs["using"].is_a?(String)
      @errors << "local action runs configuration is invalid: #{display_path(manifest)}"
      return
    end

    case runs["using"]
    when "composite"
      scan_steps(runs["steps"], "#{display_path(manifest)}: runs.steps")
    when "docker"
      validate_local_docker_action(runs, manifest)
    end
  end

  def validate_local_docker_action(runs, manifest)
    image = runs["image"]
    source = "#{display_path(manifest)}: runs.image"
    unless image.is_a?(String)
      @errors << "local Docker action image must be a string: #{source}"
      return
    end

    if image.start_with?("docker://")
      scan_uses(image, source, :action)
      return
    end

    candidate = (manifest.dirname + image).cleanpath
    unless inside?(manifest.dirname, candidate) && candidate.file?
      @errors << "local Docker action Dockerfile is missing or escapes its action directory: #{source}"
      return
    end

    resolved = candidate.realpath
    unless inside?(manifest.dirname.realpath, resolved)
      @errors << "local Docker action Dockerfile resolves outside its action directory: #{source}"
    end
  rescue Errno::ENOENT, Errno::EACCES => e
    @errors << "cannot resolve local Docker action image: #{source}: #{e.class}"
  end

  def validate_required_check
    if @validate_jobs.length != 1
      @errors << "exactly one effective job/check must be named validate; found #{@validate_jobs.length}"
      return
    end

    record = @validate_jobs.first
    workflow = record[:workflow]
    job = record[:job]
    events = workflow[:data].key?("on") ? workflow[:data]["on"] : workflow[:data][true]
    unless event_names(events).sort == ["pull_request", "push"]
      @errors << "validate workflow event set must be exactly pull_request and push: #{workflow[:relative]}"
    end
    if events.is_a?(Hash)
      pull_request_event = events["pull_request"]
      push_event = events["push"]
      pull_request_branches = pull_request_event.is_a?(Hash) ? pull_request_event["branches"] : nil
      push_branches = push_event.is_a?(Hash) ? push_event["branches"] : nil
      valid_branches = pull_request_event.is_a?(Hash) &&
        push_event.is_a?(Hash) &&
        pull_request_event.keys.map(&:to_s).sort == ["branches"] &&
        push_event.keys.map(&:to_s).sort == ["branches"] &&
        pull_request_branches.is_a?(Array) &&
        push_branches.is_a?(Array) &&
        pull_request_branches.length == 1 &&
        push_branches == pull_request_branches &&
        pull_request_branches.first.is_a?(String) &&
        pull_request_branches.first.match?(%r{\A[A-Za-z0-9._/-]+\z}) &&
        !pull_request_branches.first.include?("..") &&
        !pull_request_branches.first.start_with?("/") &&
        !pull_request_branches.first.end_with?("/")
      unless valid_branches
        @errors << "validate workflow push and pull_request must target the same single literal branch: #{workflow[:relative]}"
      end
    else
      @errors << "validate workflow events must define explicit branch filters: #{workflow[:relative]}"
    end

    root_permissions = validate_root_permissions(workflow)
    if root_permissions
      workflow[:jobs].each { |job_record| validate_job_permissions(job_record, root_permissions) }
    end

    scan_validate_credential_contexts(workflow)

    location = "#{workflow[:relative]}: jobs.#{record[:id]}"
    @errors << "validate job cannot use job-level if: #{location}" if job.key?("if")
    if job.key?("continue-on-error")
      @errors << "validate job cannot use job-level continue-on-error: #{location}"
    end
    @errors << "validate job cannot delegate to a reusable workflow: #{location}" if job.key?("uses")
    @errors << "validate job cannot depend on another job: #{location}" if job.key?("needs")
    validate_step_controls(job["steps"], "#{location}.steps", {})
    validate_job_containers(job, location)

    strategy = job["strategy"]
    if strategy.is_a?(Hash) && strategy.key?("matrix")
      @errors << "validate job cannot use a matrix because it creates multiple checks: #{location}"
    elsif job.key?("strategy") && !strategy.is_a?(Hash)
      @errors << "validate job strategy must be a static mapping: #{location}"
    end
  end

  def validate_job_containers(job, location)
    if job.key?("container")
      container = job["container"]
      image = container.is_a?(Hash) ? container["image"] : container
      validate_pinned_container_image(image, "#{location}.container.image")
    end

    return unless job.key?("services")

    services = job["services"]
    unless services.is_a?(Hash)
      @errors << "validate job services must be a static mapping: #{location}.services"
      return
    end
    services.each do |service_name, service|
      image = service.is_a?(Hash) ? service["image"] : nil
      validate_pinned_container_image(image, "#{location}.services.#{service_name}.image")
    end
  end

  def validate_pinned_container_image(image, location)
    unless image.is_a?(String) && PINNED_CONTAINER_IMAGE.match?(image)
      @errors << "validate job container image is not digest pinned: #{location}"
    end
  end

  def validate_step_controls(steps, location, visited_actions)
    return unless steps.is_a?(Array)

    steps.each_with_index do |step, index|
      next unless step.is_a?(Hash)

      step_location = "#{location}[#{index}]"
      @errors << "validate step cannot use if: #{step_location}" if step.key?("if")
      if step.key?("continue-on-error")
        @errors << "validate step cannot use continue-on-error: #{step_location}"
      end

      value = step["uses"]
      next unless value.is_a?(String) && value.start_with?("./")

      validate_local_action_step_controls(value, visited_actions)
    end
  end

  def validate_local_action_step_controls(value, visited_actions)
    directory = resolve_inside_root(value, "validate local action step-control dependency")
    return unless directory&.directory?

    manifest = [directory + "action.yml", directory + "action.yaml"].find(&:file?)
    return if manifest.nil?

    manifest = manifest.realpath
    return if visited_actions[manifest.to_s]

    visited_actions[manifest.to_s] = true
    data = load_yaml(manifest, "local action")
    return unless data.is_a?(Hash)

    runs = data["runs"]
    return unless runs.is_a?(Hash)

    if runs["using"] == "composite"
      validate_step_controls(runs["steps"], "#{display_path(manifest)}: runs.steps", visited_actions)
    elsif runs["using"] == "docker" && runs["image"].is_a?(String) && !runs["image"].start_with?("docker://")
      validate_dockerfile_bases(manifest, runs["image"])
    end
  end

  def validate_dockerfile_bases(manifest, image)
    source = "#{display_path(manifest)}: runs.image"
    dockerfile = (manifest.dirname + image).cleanpath
    return unless dockerfile.file? && inside?(manifest.dirname, dockerfile)

    lines = dockerfile.read.lines
    from_count = 0
    trusted_aliases = {}
    lines.each_with_index do |line, index|
      stripped = line.strip
      next unless stripped.match?(/\AFROM\b/i)

      from_count += 1
      location = "#{display_path(dockerfile)}:#{index + 1}"
      if stripped.end_with?("\\") || stripped.end_with?("`")
        @errors << "Dockerfile FROM continuations are not permitted: #{location}"
        next
      end
      if stripped.include?("$")
        @errors << "Dockerfile FROM must not contain dynamic expressions: #{location}"
        next
      end

      match = stripped.match(/\AFROM\s+(?:(--platform=\S+)\s+)?(\S+)(?:\s+AS\s+([A-Za-z0-9_.-]+))?\s*\z/i)
      unless match
        @errors << "Dockerfile FROM syntax cannot be safely verified: #{location}"
        next
      end

      platform = match[1]
      base_image = match[2]
      alias_name = match[3]
      if platform&.include?("$")
        @errors << "Dockerfile FROM platform must be static: #{location}"
      end

      trusted_base = base_image == "scratch" ||
                     PINNED_CONTAINER_IMAGE.match?(base_image) ||
                     trusted_aliases.key?(base_image.downcase)
      unless trusted_base
        @errors << "Dockerfile base image is not digest pinned: #{location}"
      end

      next if alias_name.nil?

      alias_key = alias_name.downcase
      if trusted_aliases.key?(alias_key)
        @errors << "Dockerfile stage alias is duplicated: #{location}"
      elsif trusted_base
        trusted_aliases[alias_key] = true
      end
    end

    if from_count.zero?
      @errors << "Dockerfile contains no verifiable FROM instruction: #{display_path(dockerfile)}"
    end
  rescue Errno::ENOENT, Errno::EACCES => e
    @errors << "cannot inspect local Docker action Dockerfile: #{source}: #{e.class}"
  end

  def scan_validate_credential_contexts(workflow)
    visited_workflows = { workflow[:path].expand_path.to_s => true }
    visited_actions = {}
    scan_forbidden_contexts(workflow[:data], workflow[:relative])
    scan_workflow_credentials(workflow[:data], visited_workflows, visited_actions)
  end

  def scan_workflow_credentials(data, visited_workflows, visited_actions)
    jobs = data["jobs"]
    return unless jobs.is_a?(Hash)

    jobs.each_value do |job|
      next unless job.is_a?(Hash)

      if job["uses"].is_a?(String) && job["uses"].start_with?("./")
        target = resolve_inside_root(job["uses"], "validate dependency")
        if target&.file? && !visited_workflows[target.to_s]
          visited_workflows[target.to_s] = true
          dependency = load_yaml(target, "local reusable workflow")
          if dependency.is_a?(Hash)
            scan_forbidden_contexts(dependency, display_path(target))
            scan_workflow_credentials(dependency, visited_workflows, visited_actions)
          end
        end
      end

      scan_step_credentials(job["steps"], visited_workflows, visited_actions)
    end
  end

  def scan_step_credentials(steps, visited_workflows, visited_actions)
    return unless steps.is_a?(Array)

    steps.each do |step|
      next unless step.is_a?(Hash)

      value = step["uses"]
      next unless value.is_a?(String) && value.start_with?("./")

      scan_local_action_credentials(value, visited_workflows, visited_actions)
    end
  end

  def scan_local_action_credentials(value, visited_workflows, visited_actions)
    directory = resolve_inside_root(value, "validate local action dependency")
    return unless directory&.directory?

    manifest = [directory + "action.yml", directory + "action.yaml"].find(&:file?)
    return if manifest.nil?

    manifest = manifest.realpath
    return if visited_actions[manifest.to_s]

    visited_actions[manifest.to_s] = true
    data = load_yaml(manifest, "local action")
    return unless data.is_a?(Hash)

    scan_forbidden_contexts(data, display_path(manifest))
    runs = data["runs"]
    return unless runs.is_a?(Hash) && runs["using"] == "composite"

    scan_step_credentials(runs["steps"], visited_workflows, visited_actions)
  end

  def validate_root_permissions(workflow)
    permissions = workflow[:data]["permissions"]
    return { mode: :read_all } if permissions == "read-all"
    if permissions.is_a?(Hash) && permissions.length == 1 && permissions["contents"] == "read"
      return { mode: :contents_read }
    end

    @errors << "validate workflow root permissions must be read-all or only contents: read: #{workflow[:relative]}"
    nil
  end

  def validate_job_permissions(job_record, root_permissions)
    job = job_record[:job]
    return unless job.key?("permissions")

    permissions = job["permissions"]
    location = "#{job_record[:workflow][:relative]}: jobs.#{job_record[:id]}.permissions"
    if permissions == "read-all"
      unless root_permissions[:mode] == :read_all
        @errors << "job-level permissions escalate beyond workflow permissions: #{location}"
      end
      return
    end

    unless permissions.is_a?(Hash)
      @errors << "job-level permissions must be a static mapping or read-all: #{location}"
      return
    end

    permissions.each do |scope, access|
      unless access == "read" || access == "none"
        @errors << "job-level permission is not read-only: #{location}.#{scope}"
        next
      end
      if root_permissions[:mode] == :contents_read && access == "read" && scope.to_s != "contents"
        @errors << "job-level permissions escalate beyond contents: read: #{location}.#{scope}"
      end
    end
  end
end

validator = WorkflowSecurityValidator.new(Dir.pwd).run

unless validator.success?
  validator.errors.each { |error| warn("ERROR: #{error}") }
  warn("Workflow security validation failed with #{validator.errors.length} error(s).")
  exit 1
end

puts "Workflow security validation passed for #{validator.summary}."
