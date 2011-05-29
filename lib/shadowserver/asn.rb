require 'socket'

module Shadowserver
	class ASN
		@@server = 'asn.shadowserver.org'
		@@port = 43
		def ASN::origin(ip)
			t = TCPSocket.new(@@server,@@port)
			t.write("origin #{ip}\n")
			asn, cidr, asname, cc, domain, isp = t.read.chomp.split(/\|/).map{|x| x.strip}
			asn = asn.to_i
			t.close
			{
				"asn" => asn,
				"cidr" => cidr,
				"asname" => asname,
				"cc" => cc,
				"domain" => domain,
				"isp" => isp
			}
		end

		def ASN::peer(ip)
			t = TCPSocket.new(@@server,@@port)
			t.write("peer #{ip}\n")
			peers, asn, prefix, asname, cc, domain, isp = t.read.chomp.split(/\|/).map{|x| x.strip}
			asn = asn.to_i
			peers = peers.split(/ /).map{|x| x.to_i}
			t.close
			{
				"peers" => peers,
				"asn" => asn,
				"prefix" => prefix,
				"asname" => asname,
				"cc" => cc,
				"domain" => domain,
				"isp" => isp
			}
		end

		def ASN::prefix(asn)
			t = TCPSocket.new(@@server,@@port)
			t.write("prefix #{asn}\n")
			prefixes = t.read.chomp.split(/\n/)
			t.close
			prefixes
		end
	end
end