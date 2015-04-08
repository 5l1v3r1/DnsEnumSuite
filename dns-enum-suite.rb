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
require 'whois'
require 'net/http'
require 'json'

class String
  def red; colorize(self, "\e[1m\e[31m"); end
  def green; colorize(self, "\e[1m\e[32m"); end
  def dark_green; colorize(self, "\e[32m"); end
  def yellow; colorize(self, "\e[1m\e[33m"); end
  def blue; colorize(self, "\e[1m\e[34m"); end
  def dark_blue; colorize(self, "\e[34m"); end
  def purple; colorize(self, "\e[35m"); end
  def dark_purple; colorize(self, "\e[1;35m"); end
  def dark_cyan; colorize(self, "\e[36m"); end
  def cyan; colorize(self, "\e[1;36m"); end
  def pure; colorize(self, "\e[1m\e[35m"); end
  def bold; colorize(self, "\e[1m"); end
  def colorize(text, color_code)  "#{color_code}#{text}\e[0m" end

  def title
    "#{self}: ".dark_cyan
  end
end

$main_mark = "|-> ".cyan
$good_mark = "[+] ".cyan

# TODO : TO BE REMOVED!
# def dnstest
#   # http://www.rubydoc.info/gems/net-dns/Net/DNS/Packet#each_address-instance_method
#   packet = Net::DNS::Resolver.start(domain, Net::DNS::ANY)
#   header = packet.header
#   answer = packet.answer
#   addresses = packet.each_address {|ip| p ip.to_s }
#   mx = packet.each_mx {|txt , ip| p ip}
#   nameserver = packet.each_nameserver {|s| p s.to_s}
# end



class DNSEnumSuite
  attr_reader :domain, :nameservers, :whois
  attr_accessor :datastore

  def initialize(domain)
    @domain = domain
    @packet = Net::DNS::Resolver.start(domain, Net::DNS::ANY)
    @nameservers = nameservers
    @whois = Whois::Client.new.lookup(domain)
    @datastore = []
  end


  #
  # DNS lookup
  #
  def lookup(domain = nil)
    ips = []
    if domain.nil?
      @packet.each_address {|ip| ips << ip.to_s }
    else
      packet = Net::DNS::Resolver.start(domain, Net::DNS::ANY)
      packet.each_address {|ip| ips << ip.to_s }
    end

    return ips.sort
  end

  def reverse_lookup(ip)
    ptrs = []
    packet = Net::DNS::Resolver.start(ip, Net::DNS::PTR)
    packet.each_ptr {|ptr| ptrs << ptr.delete(" ")}

    return {ip => ptrs}
  end

  def nameservers
    ns = {}
    @packet.each_nameserver do |name|
      ns[name] = Net::DNS::Resolver.start(name).answer[0].address.to_s
    end

    return ns
  end

  #
  # MX Records
  #
  def mx
    mx = {}
    @packet.each_mx do |v, mxname|
      Net::DNS::Resolver.start(mxname).each_address {|ip| mx[mxname] = ip.to_s}
    end

    return mx
  end

  #
  # Zone Transfer
  #
  def zone_transfer
    axfr = Net::DNS::Resolver.new(nameserver: nameservers.values).axfr(@domain)
    if axfr.header.anCount > 0
      return axfr.answer
    else
      return false
    end
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




#
# Showtime!
#
begin
  options = {}
  optparse = OptionParser.new do|opts|
    opts.separator "Help menu:".bold
    opts.on('-d', '--domain DOMAIN', 'Domain to enumerate.') { |v| options[:domain] = v }
    opts.on('-n', '--nameserver [NAMESERVER]', 'Name server to use due enumeration. Use domain\'s related nameserver for better result ') { |v| options[:nameserver] = v }
    opts.on('-w', '--wordlist [WORDLIST_FILE]', 'Use wordlist file to enumerate the given domain') { |v| options[:wordlist] = v }
    opts.on('-a', '--aggressive', 'Aggressive Bruteforce.') { |v| options[:aggressive] = v } # TODO: make aggressive with level chosen
    opts.on('-v', '--version', 'Current version.') { |v| options[:domain] = v }

    #--> Help screen
    opts.banner = "\nUsage:".bold + "\n ruby #{__FILE__} {OPTIONS} DOMAIN [OPTIONS]\n\n"
    opts.on( '-h', '--help', "Display help screen \n" ) 	do
      puts "#{opts}"

      puts "\nExample:\n".bold +
               "ruby #{__FILE__} --domain domain.com\n" 	+
               "ruby #{__FILE__} -d domain.com --nameserver et02.maileig.com,et02.maileig.com\n" 	+
               "ruby #{__FILE__} -d domain.com --wordlist /path/to/wordlist.txt\n\n"

      exit
    end
  end
  optparse.parse!
  options
  ARGV



  case
    when options[:domain]

      @dnsenum = DNSEnumSuite.new(options[:domain])

      # if options[:type] == nil
      #   type = "No format specified."
      # else
      #   type = options[:type]
      # end
      # puts "Domainnn".red
      # puts "Domainnn".blue
      # puts "Domainnn".dark_blue
      # puts "Domainnn".green
      # puts "Domainnn".dark_green
      # puts "Domainnn".yellow
      # puts "Domainnn".bold
      # puts "Domainnn".purple
      # puts "Domainnn".dark_purple
      # puts "Domainnn".cyan
      # puts "Domainnn".dark_cyan
      # puts "Domainnn\n\n"



      puts $main_mark + "Whois".title + "#{options[:domain]}"
      # puts @dnsenum.whois

      puts ""
      puts $main_mark + "Forward lookup".title
      @dnsenum.lookup.each do |ip|
        puts "#{@dnsenum.domain}".ljust(30) + "#{ip}"
      end

      puts ""
      puts $main_mark + "Name Servers".title
      @dnsenum.nameservers.each do |k, v|
        puts "#{k}".ljust(30) + "#{v}"
      end

      puts ""
      puts $main_mark + "Mail Servers".title + "#{options[:domain]}"
      @dnsenum.mx.each do |k, v|
        puts "#{k}".ljust(30) + "#{v}"
      end


      puts ""
      puts $main_mark + "Zone Transfer".title + "#{options[:domain]}"
      if @dnsenum.zone_transfer == false
        puts $good_mark + "Zone Transfer disabled!"
      else
        puts @dnsenum.zone_transfer
      end

      #
      # Enable wordlist
      #
      if options[:wordlist]
        puts ""
        wordlist = File.readlines options[:wordlist]
        puts $main_mark + "DNS Bruteforce - wordlist (#{wordlist.size} words)".title + "#{options[:domain]}"
        puts "\nIP Address".ljust(21) + "Domain".ljust(30) + "Country"
        puts "-" * 70

        wordlist.each do |sub|
          fqdn = "#{sub.chomp!}.#{@dnsenum.domain}"
          print "Bruteforcing ".purple + " #{sub}.#{@dnsenum.domain}" + "\r"

          unless @dnsenum.lookup(fqdn).empty?
            puts "#{@dnsenum.lookup(fqdn).first}".ljust(20) + "#{fqdn}".ljust(30) + "#{@dnsenum.geoip(@dnsenum.lookup(fqdn).first)["city"]}/#{@dnsenum.geoip(@dnsenum.lookup(fqdn).first)["country"]}"
          end

          print  ("\e[K")
        end
      end


      if options[:aggressive]

        puts ""
        puts $main_mark + "DNS Bruteforce - Aggressive (Level #1)".title + "From aaa To zzz"
        @dnsenum.gen_list("aaa-zzzz").each do |sub|
          fqdn = "#{sub}.#{@dnsenum.domain}"
          print "Bruteforcing ".purple + " #{sub}.#{@dnsenum.domain}" + "\r"

          unless @dnsenum.lookup(fqdn).empty?
            puts "#{@dnsenum.lookup(fqdn).first}".ljust(20) + "#{fqdn}".ljust(30) + "#{@dnsenum.geoip(@dnsenum.lookup(fqdn).first)["city"]}/#{@dnsenum.geoip(@dnsenum.lookup(fqdn).first)["country"]}"
          end

          print  ("\e[K")
        end



        # puts ""
        # puts $main_mark + "DNS Bruteforce - Aggressive (Level #2)".title + "From aaaa To zzzz"
        # @dnsenum.gen_list("aaaa-zzzz").each do |sub|
        #   fqdn = "#{sub}.#{@dnsenum.domain}"
        #   print "Bruteforcing ".purple + " #{sub}.#{@dnsenum.domain}" + "\r"
        #
        #   unless @dnsenum.lookup(fqdn).empty?
        #     puts "#{@dnsenum.lookup(fqdn).first}".ljust(20) + "#{fqdn}".ljust(30) + "#{@dnsenum.geoip(@dnsenum.lookup(fqdn).first)["city"]}/#{@dnsenum.geoip(@dnsenum.lookup(fqdn).first)["country"]}"
        #   end
        #
        #   print  ("\e[K")
        # end
        #
        #
        #
        # puts ""
        # puts $main_mark + "DNS Bruteforce - Aggressive (Level #2)".title + "From aaaaa To zzzzz"
        # @dnsenum.gen_list("aaaaa-zzzzz").each do |sub|
        #   fqdn = "#{sub}.#{@dnsenum.domain}"
        #   print "Bruteforcing ".purple + " #{sub}.#{@dnsenum.domain}" + "\r"
        #
        #   unless @dnsenum.lookup(fqdn).empty?
        #     puts "#{@dnsenum.lookup(fqdn).first}".ljust(20) + "#{fqdn}".ljust(30) + "#{@dnsenum.geoip(@dnsenum.lookup(fqdn).first)["city"]}/#{@dnsenum.geoip(@dnsenum.lookup(fqdn).first)["country"]}"
        #   end
        #
        #   print  ("\e[K")
        # end

      end


      # puts ""
      # puts $main_mark + "Reverse Lookup".title + "#{options[:domain]}"
      #
      # @dnsenum.ip_range("").each do |ip|
      #   print "Bruteforcing ".purple + " #{ip}" + "\r"
      #
      #   p @dnsenum.reverse_lookup(ip)
      #   unless @dnsenum.reverse_lookup(ip).empty?
      #     puts "#{ip}".ljust(20) + "#{@dnsenum.reverse_lookup(ip)}"
      #   end
      #
      #   print  ("\e[K")
      # end


      puts ""
      # puts $main_mark + "TTTTTT".title + "#{options[:domain]}"

      puts ""
      puts $main_mark + "Final Report".title + "#{options[:domain]}"
      puts "TO BE IMPLEMENTED"


    else
      puts "#{optparse}"
  end

rescue OptionParser::InvalidOption, OptionParser::MissingArgument, OptionParser::NO_ARGUMENT
  puts "#{optparse}"
end






