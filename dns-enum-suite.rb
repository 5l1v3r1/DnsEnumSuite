#!/usr/bin/env ruby
#
# DNS Enum Suite
#
# - DNS forward enum
# - Reverse
# - DNS bruteforce
#   - Predictable words
#     - From metasploit and fierce
#     - From city names and shortname
#
#
#   - Damn A-Z words
# - IP range
# - GeoIP of each IP (http://ip-api.com/docs/dns , http://ip-api.com/docs/)
# -
#

require 'optparse'
require 'net/dns'
require 'net/http'
require 'json'

class String
  def red; colorize(self, "\e[1m\e[31m"); end
  def green; colorize(self, "\e[1m\e[32m"); end
  def dark_green; colorize(self, "\e[32m"); end
  def yellow; colorize(self, "\e[1m\e[33m"); end
  def blue; colorize(self, "\e[1m\e[34m"); end
  def dark_blue; colorize(self, "\e[34m"); end
  def pur; colorize(self, "\e[1m\e[35m"); end
  def bold; colorize(self, "\e[1m"); end
  def colorize(text, color_code)  "#{color_code}#{text}\e[0m" end
end


# TODO : TO BE REMOVED!
def dnstest
  # http://www.rubydoc.info/gems/net-dns/Net/DNS/Packet#each_address-instance_method
  packet = Net::DNS::Resolver.start(domain, Net::DNS::ANY)
  header = packet.header
  answer = packet.answer
  addresses = packet.each_address {|ip| p ip.to_s }
  mx = packet.each_mx {|txt , ip| p ip}
  nameserver = packet.each_nameserver {|s| p s.to_s}
end



class DNSEnumSuite
  attr_reader :domain, :nameservers, :whois

  def initialize(domain)
    @domain = domain
    @packet = Net::DNS::Resolver.start(domain, Net::DNS::ANY)
    @lists = ["1-100", "a-z", "a1-z9", "aa-zz", "aaa-zzz", "aaaa-zzzz", "aaaaa-zzzzz"]
    @nameservers = nameservers
    @whois = Whois::Client.new.lookup(domain)
  end


  #
  # DNS lookup
  #
  def lookup(domain = @domain)
    ips = []
    packet = Net::DNS::Resolver.start(domain, Net::DNS::ANY)
    packet.each_address {|ip| ips << ip.to_s }

    return ips.sort
  end

  def reverse_lookup(ip)
    ptrs = []
    packet = Net::DNS::Resolver.start(ip, Net::DNS::PTR)
    packet.each_ptr {|ptr| ptrs << ptr.delete(" ")}

    return {ip => ptrs}.sort
  end

  def nameservers
    ns = {}
    @packet.each_nameserver do |name|
      ns[name] = Net::DNS::Resolver.start(name).answer[0].address.to_s
    end

    return ns.sort
  end


  #
  # Get IP Geolocation
  #   It gets the geolocation of host(domain/ip) information from ip-api.com as Json response
  # *example:*
  #   puts geoip(host)["city"]
  #   puts geoip(host)["countryCode"]
  #   puts geoip(host)["query"]
  #   puts geoip(host)["isp"]
  def geoip(host)
    response = Net::HTTP.get_response(URI.parse("http://ip-api.com/json/#{host}")).body
    _geoip = JSON.parse response

    return _geoip
  end


  #
  # Generate list of characters with given size
  # range = Start-End - it's the starting and ending characters
  # size the size of the range character.
  #   *ex.* list_gen("a-z", 3) = all characters from 'aaa' to 'zzz'
  #
  def gen_list(range)
    range = range.split('-')

    if range[1].size > 5
      puts "[!]" + "From #{range[0]} to #{range[1]} would take very long time! please use size <= 5"
      exit(0)
    end

    (range[0]..range[1]).to_a
  end

  def ip_range(ip)
    _ip = ip.split('.')
    ip_list = (1..254).to_a.map { |oct| _ip[3] = "#{oct}" ; _ip.join('.') }

    return ip_list
  end


end




begin

  options = {}
  OptionParser.new do |opts|
    opts.banner = "Usage: ruby #{__FILE__}.rb [options]"

    opts.on('-d', '--domain DOMAIN', 'Domain to enumerate.') { |v| options[:domain] = v }
    opts.on('-n', '--nameserver NAMESERVER', 'Name server to use due enumeration. Use domain\'s related nameserver for better result ') { |v| options[:source_host] = v }
    opts.on('-r', '--range START-END:SIZE', 'Starting and Ending range of enumeration characters with size. ex. a-z:3 = all characters from "aaa" to "zzz"') { |v| options[:range] = v }
    opts.on('-i', '--ipaddress-range [X.X.X.X-Z]', 'Aggressive enumeration [Default]. All possible enumeration techniques - takes long time ') { |v| options[:aggressive] = v }
    opts.on('-w', '--wordless [WORDLIST_FILE]', 'Use wordslist file to enumerate the given domain') { |v| options[:wordless] = v }
    opts.on('-a', '--aggressive', 'Aggressive enumeration [Default]. All possible enumeration techniques - takes long time ') { |v| options[:aggressive] = v }

  end.parse!


  case

    when options[:domain]
      puts "Domain!"

    when options[:range]
      puts "range"

  end


rescue  OptionParser::InvalidOption, OptionParser::MissingArgument, OptionParser::NO_ARGUMENT

  puts "#{optparse}"

end









