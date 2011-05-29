require 'net/http'
require 'digest/sha1'
require 'uri'
require 'json'

module Shadowserver
	class Whitelist
		@@baseurl = "http://bin-test.shadowserver.org/api"
		def Whitelist::by_hash(hash)
			url = @@baseurl
			if hash.length == 32
				url += "?md5=#{hash.upcase}"
			elsif hash.length == 40
				url += "?sha1=#{hash.upcase}"
			else
				raise "The hash must be either 32 or 40 characters long"
			end
			url = URI.parse(url)
			request = Net::HTTP::Get.new(url.path+"?"+url.query)
			request.add_field("User-Agent", "Ruby/#{RUBY_VERSION} shadowserver rubygem (https://github.com/chrislee35/shadowserver)")
			http = Net::HTTP.new(url.host, url.port)
			if url.scheme == 'https'
				http.use_ssl = true
				http.verify_mode = OpenSSL::SSL::VERIFY_NONE
				http.verify_depth = 5
			end
			resp = http.request(request)
			if resp.body =~ /^[0-9A-F]{32,40} (.+)/
				JSON.parse($1)
			else
				nil
			end
		end
		def Whitelist::by_filename(filename)
			if File.exists?(filename)
				hash = Digest::SHA1.hexdigest(File.open(filename).read)
			else
				raise "Whitelist::by_filename: Could not find file, #{filename}"
			end
			Whitelist::by_hash(hash)
		end
		def Whitelist::by_string(string)
			hash = Digest::SHA1.hexdigest(string)
			Whitelist::by_hash(hash)
		end
	end
end