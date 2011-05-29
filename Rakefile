require 'rubygems'
require 'bundler'
begin
	Bundler.setup(:default, :development)
rescue Bundler::BundlerError => e
	$stderr.puts e.message
	$stderr.puts "Run `bundle install` to install missing gems"
	exit e.status_code
end
require 'rake'

require 'jeweler'
Jeweler::Tasks.new do |gem|
	# gem is a Gem::Specification... see http://docs.rubygems.org/read/chapter/20 for more options
	gem.name = "shadowserver"
	gem.homepage = "http://github.com/chrislee35/shadowserver"
	gem.license = "MIT"
	gem.summary = %Q{Queries various Shadowserver services for ASN information, malware hash lookups, and whitelist hash lookups}
	gem.description = %Q{The Shadowserver Foundation is an all volunteer watchdog group of security professionals that gather, track, and report on malware, botnet activity, and electronic fraud. It is the mission of the Shadowserver Foundation to improve the security of the Internet by raising awareness of the presence of compromised servers, malicious attackers, and the spread of malware.}
	gem.email = "rubygems@chrislee.dhs.org"
	gem.authors = ["Chris Lee"]
	gem.executables = ["shadowserver_asn", "shadowserver_whitelist", "shadowserver_malware"]
	# Include your dependencies below. Runtime dependencies are required when using your gem,
	# and development dependencies are only needed for development (ie running rake tasks, tests, etc)
	gem.add_runtime_dependency "json", ">= 1.4.3"
end
Jeweler::RubygemsDotOrgTasks.new

require 'rake/testtask'
Rake::TestTask.new(:test) do |test|
	test.libs << 'lib' << 'test'
	test.pattern = 'test/**/test_*.rb'
	test.verbose = true
end

require 'rcov/rcovtask'
Rcov::RcovTask.new do |test|
	test.libs << 'test'
	test.pattern = 'test/**/test_*.rb'
	test.verbose = true
end

task :default => :test

require 'rake/rdoctask'
Rake::RDocTask.new do |rdoc|
	version = File.exist?('VERSION') ? File.read('VERSION') : ""

	rdoc.rdoc_dir = 'rdoc'
	rdoc.title = "shadowserver #{version}"
	rdoc.rdoc_files.include('README*')
	rdoc.rdoc_files.include('lib/**/*.rb')
end
