require 'helper'

class TestShadowserver < Test::Unit::TestCase
	should "return whitelist results for 0E53C14A3E48D94FF596A2824307B492" do
		w = Shadowserver::Whitelist.by_hash("0E53C14A3E48D94FF596A2824307B492")
		assert_not_nil(w)
		assert_equal({"source_version"=>"$version", "language"=>"English", "os_name"=>"Windows NT", "mfg_name"=>"Corel Corporation", "filesize"=>"2226", "os_version"=>"Generic", "product_name"=>"Gallery", "filename"=>"00br2026.gif", "crc32"=>"AA6A7B16", "application_type"=>"Graphic/Drawing", "source"=>"NIST", "os_mfg"=>"Microsoft", "product_version"=>"750,000"}, w)
	end

	should "return nil for whitelist query for 0E53C14A3E48D94FF596A2824307B493" do
		w = Shadowserver::Whitelist.by_hash("0E53C14A3E48D94FF596A2824307B493")
		assert_nil(w)
	end
	
	should "return whitelist results for notepad.exe" do
		w = Shadowserver::Whitelist.by_filename("test/notepad.exe")
		assert_not_nil(w)
		assert_equal({"source_version"=>"$version", "language"=>"English", "os_name"=>"Unknown", "mfg_name"=>"Sony", "filesize"=>"66048", "os_version"=>"Unknown", "product_name"=>"VAIO Computer Quick Start", "filename"=>"NOTEPAD.EXE", "crc32"=>"0BE7841C", "application_type"=>"System Software,System restoration", "source"=>"NIST", "os_mfg"=>"Unknown", "product_version"=>"Version G186.0"}, w)
	end
	
	should "return whitelist results for the string version of notepad.exe" do
		w = Shadowserver::Whitelist.by_string(File.new("test/notepad.exe").read)
		assert_not_nil(w)
		assert_equal({"source_version"=>"$version", "language"=>"English", "os_name"=>"Unknown", "mfg_name"=>"Sony", "filesize"=>"66048", "os_version"=>"Unknown", "product_name"=>"VAIO Computer Quick Start", "filename"=>"NOTEPAD.EXE", "crc32"=>"0BE7841C", "application_type"=>"System Software,System restoration", "source"=>"NIST", "os_mfg"=>"Unknown", "product_version"=>"Version G186.0"}, w)
	end
	
	should "return malware results for aca4aad254280d25e74c82d440b76f79" do
		mr = Shadowserver::Malware.query("aca4aad254280d25e74c82d440b76f79")
		assert_equal({"first_seen"=>"2010-06-15 03:09:41", "filetype"=>"exe", "avresults"=>{"TrendMicro"=>"TROJ_DLOADR.SMM", "AntiVir"=>"WORM/VB.NVA", "VirusBuster"=>"Worm.VB.FMYJ", "QuickHeal"=>"Worm.VB.at", "Clam"=>"Trojan.Downloader-50691", "VBA32"=>"Trojan.VBO.011858", "Sophos"=>"Troj/DwnLdr-HQY", "NOD32"=>"Win32/AutoRun.VB.JP", "Kaspersky"=>"Trojan.Win32.Cosmu.nyl", "Panda"=>"W32/OverDoom.A", "Vexira"=>"Trojan.DL.VB.EEDT", "G-Data"=>"Trojan.Generic.2609117", "Ikarus"=>"Trojan-Downloader.Win32.VB", "Norman"=>"Suspicious_Gen2.SKLJ", "McAfee"=>"Generic", "AVG7"=>"Downloader.Generic9.URM", "F-Secure"=>"Worm:W32/Revois.gen!A", "F-Prot6"=>"W32/Worm.BAOX", "DrWeb"=>"Win32.HLLW.Autoruner.6014", "Avast-Commercial"=>"Win32:Zbot-LRA"}, "ssdeep"=>"12288:gOqOB0v2eZJys73dOvXDpNjNe8NuMpX4aBaa48L/93zKnP6ppgg2HFZlxVPbZX:sOA2eZJ8NI8Nah8L/4PqmTVPlX", "sha1"=>"6fe80e56ad4de610304bab1675ce84d16ab6988e", "last_seen"=>"2010-06-15 03:09:41", "md5"=>"aca4aad254280d25e74c82d440b76f79"}, mr)
	end
	
	should "return nil for malware query for 0E53C14A3E48D94FF596A2824307B492" do
		mr = Shadowserver::Malware.query("0E53C14A3E48D94FF596A2824307B492")
		assert_nil(mr)
	end
	
	should "return origin for 4.2.2.5" do
		a = Shadowserver::ASN.origin("4.2.2.5")
		assert_not_nil(a)
		assert_equal({"cc"=>"US", "domain"=>"LEVEL3.NET", "isp"=>"LEVEL 3 COMMUNICATIONS INC", "asn"=>3356, "asname"=>"LEVEL3", "cidr"=>"4.0.0.0/9"}, a)
	end
	
	should "return peer for 4.2.2.5" do
		a = Shadowserver::ASN.peer("4.2.2.5")
		assert_not_nil(a)
		assert_equal({"cc"=>"US", "prefix"=>"4.0.0.0/9", "domain"=>"LEVEL3.NET", "isp"=>"LEVEL 3 COMMUNICATIONS INC", "asn"=>3356, "asname"=>"LEVEL3", "peers"=>[701, 1239]}, a)
	end
	
	should "retun prefixes for AS2637" do
		a = Shadowserver::ASN.prefix(2637)
		assert_not_nil(a)
		assert_equal(["128.61.0.0/19", "128.61.32.0/19", "128.61.64.0/18", "128.61.128.0/17", "130.207.0.0/16", "143.215.0.0/16", "204.152.10.0/23"], a)
	end
end
