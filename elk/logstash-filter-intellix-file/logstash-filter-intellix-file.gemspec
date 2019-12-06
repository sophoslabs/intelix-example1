Gem::Specification.new do |s|
  s.name          = 'logstash-filter-intellix-file'
  s.version       = '0.1.0'
  s.licenses      = ['Apache-2.0']
  s.summary       = 'Sophoslabs Intellix lookup'
  s.description   = 'Playground for looking up file sha256'
  s.authors       = ['']
  s.email         = ''
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  s.add_runtime_dependency "rest-client", "~> 2.0"
  s.add_runtime_dependency "vine", "~> 0.4"
  s.add_runtime_dependency "json", "~> 1.8"
  s.add_runtime_dependency "oauth2", "~> 1.4"

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_development_dependency 'logstash-devutils'
end
