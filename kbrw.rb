#!/usr/bin/ruby

require 'json'
require 'curb'
require 'getopt/std'

opt = Getopt::Std.getopts("s:t:")
puts "Get network info for kbrw_private"
kbrw_network = nil
kbrw_vmipv4 = nil
kbrw_vmipv6 = nil
kbrw_sg = nil
ingress = []
egress = []

#Retrieve url
def get_info (url,token)
  Curl::Easy.new(url) do |curl| 
    curl.headers={}
    curl.headers["X-Auth-Token"] = token
    curl.headers["Content-Type"] = "application/json"
    curl.headers["Accept"] = "application/json"
    #curl.verbose = true
    curl.perform
    return JSON.parse(curl.body_str)
  end
end

def post_json (url,token,options)
  #url = "https://network.compute.sbg-1.runabove.io/v2.0/networks"
  Curl::Easy.new(url) do |curl| 
    curl.headers["X-Auth-Token"] = token
    curl.headers["Content-Type"] = ["application/json"]
    curl.headers["Accept"] = "application/json"
    curl.http_post(options)
    #curl.verbose = true
    return JSON.parse(curl.body_str)
  end
end

#{"networks"=>[{"status"=>"ACTIVE", "subnets"=>["f0b10c59-bd05-460c-953f-eddd31d2de96", "f96f70f3-07fa-44cb-9a52-9fb1d552410c"], "name"=>"private", "router:external"=>false, "tenant_id"=>"ec58c087117441159c74e74c55d87f29", "admin_state_up"=>true, "shared"=>false, "id"=>"d24612cd-4e49-408e-9b07-bfae104d6530"}, {"status"=>"ACTIVE", "subnets"=>[], "name"=>"kbrw_private", "router:external"=>false, "tenant_id"=>"ec58c087117441159c74e74c55d87f29", "admin_state_up"=>true, "shared"=>false, "id"=>"d4110b67-ae79-48de-be31-1e0fc35305af"}, {"status"=>"ACTIVE", "subnets"=>["2c56a226-e78b-4268-b3d4-96e61e4fc0fe"], "name"=>"Ext-Net", "router:external"=>true, "tenant_id"=>"b6bc4198c6b54b3abe083200d69790cb", "admin_state_up"=>true, "shared"=>true, "id"=>"f5cc56db-db25-4488-8371-c507951b2631"}]}
#networks = JSON.parse(c_network.body_str)
#p json
networks=get_info("https://network.compute.sbg-1.runabove.io/v2.0/networks",token)

networks["networks"].each do |net|
  if net["name"] == "kbrw_private"
    if ! kbrw_network.nil?
      raise 'Two or more networks named kbrw_private'
    end
    kbrw_network = net["id"]
  end
end

if kbrw_network.nil?
  puts "Network not found, creating ..."
  networks=post_json("https://network.compute.sbg-1.runabove.io/v2.0/networks",token,'{"network":{"name":"kbrw_private","admin_state_up":true}}')
  networks.each do |netw,net|
    if net["name"] == "kbrw_private"
      kbrw_network = net["id"]
      puts "Network created"
    end
  end
end

if kbrw_network
  puts "Network exist : #{kbrw_network}"
  puts "Searching for existing Subnet"
  #{"subnets": [{"name": "", "enable_dhcp": true, "network_id": "f5cc56db-db25-4488-8371-c507951b2631", "tenant_id": "b6bc4198c6b54b3abe083200d69790cb", "dns_nameservers": ["213.186.33.99"], "allocation_pools": [{"start": "92.222.64.1", "end": "92.222.95.254"}], "host_routes": [], "ip_version": 4, "gateway_ip": "92.222.53.226", "cidr": "92.222.64.0/19", "id": "2c56a226-e78b-4268-b3d4-96e61e4fc0fe"}, {"name": "vm", "enable_dhcp": false, "network_id": "d24612cd-4e49-408e-9b07-bfae104d6530", "tenant_id": "ec58c087117441159c74e74c55d87f29", "dns_nameservers": ["8.8.8.8"], "allocation_pools": [{"start": "10.0.255.20", "end": "10.0.255.120"}], "host_routes": [{"nexthop": "10.0.255.1", "destination": "172.16.0.0/12"}], "ip_version": 4, "gateway_ip": "10.0.255.1", "cidr": "10.0.255.0/24", "id": "f0b10c59-bd05-460c-953f-eddd31d2de96"}, {"name": "vm ipv6", "enable_dhcp": false, "network_id": "d24612cd-4e49-408e-9b07-bfae104d6530", "tenant_id": "ec58c087117441159c74e74c55d87f29", "dns_nameservers": [], "allocation_pools": [{"start": "2001:41d0:9a:b000::2", "end": "2001:41d0:9a:b000:ffff:ffff:ffff:fffe"}], "host_routes": [], "ip_version": 6, "gateway_ip": "2001:41d0:9a:b000::1", "cidr": "2001:41d0:9a:b000::/64", "id": "f96f70f3-07fa-44cb-9a52-9fb1d552410c"}]}
  subnets=get_info("https://network.compute.sbg-1.runabove.io/v2.0/subnets",token)
  subnets["subnets"].each do |net|
    #puts net
    case net["name"]
    when "kbrw_vmipv4"
      if net["network_id"] == kbrw_network
        puts 'Subnet kbrw_ipv4 for network kbrw_network already exist'
        kbrw_vmipv4 = net["id"]
      end
    when "kbrw_vmipv6"
      if net["network_id"] == kbrw_network
        puts 'Subnet kbrw_ipv6 for network kbrw_network already exist'
        kbrw_vmipv6 = net["id"]
      end
    end
  end
end

if kbrw_vmipv4.nil?
  puts "Ipv4 subnet not found"
  puts "Ipv4 subnet creating"
  networks=post_json("https://network.compute.sbg-1.runabove.io/v2.0/subnets",token,'{"subnet":{"name":"kbrw_vmipv4","ip_version":4,"cidr":"10.0.255.0/24","enable_dhcp":false,"network_id":"%{id}"}}' % [id: kbrw_network])
  networks.each do |netw,net|
    if net["name"] == "kbrw_vmipv4"
      kbrw_vmipv4 = net["id"]
      puts "Subnet created"
    else
      raise net["message"]
    end
  end
end

if kbrw_vmipv6.nil?
  puts "Ipv6 subnet not found"
  puts "Ipv6 subnet creating"
  networks=post_json("https://network.compute.sbg-1.runabove.io/v2.0/subnets",token,'{"subnet":{"name":"kbrw_vmipv6","ip_version":6,"cidr":"2001:41d0:9a:b000::/64","enable_dhcp":false,"network_id":"%{id}"}}' % [id: kbrw_network])
  networks.each do |netw,net|
    if net["name"] == "kbrw_vmipv6"
      kbrw_vmipv6 = net["id"]
      puts "Subnet created"
    else
      raise net["message"]
    end
  end
end

sg=get_info("https://network.compute.sbg-1.runabove.io/v2.0/security-groups",token)
sg.each do |secw,secg|
  secg.each do |sec|
    if sec["name"] == "kbrw_sg"
      if ! kbrw_sg.nil?
        raise 'Two or more sg named kbrw_sg'
      end
      kbrw_sg = sec["id"]
    end
  end
end

if kbrw_sg.nil?
  puts "Creating Security Group kbrw_sg"
  sg=post_json("https://network.compute.sbg-1.runabove.io/v2.0/security-groups",token,'{"security_group":{"name":"kbrw_sg","description":"Kbrw sg"}}')
  sg.each do |secg,sec|
    if sec["name"] == "kbrw_sg"
      kbrw_sg = sec["id"]
      puts "Security Group created"
    else
      raise sec["message"]
    end
  end
else
  puts "Security Group kbrw_sg already exist"
end

sglist=get_info("https://network.compute.sbg-1.runabove.io/v2.0/security-groups/#{kbrw_sg}",token)
sglist.each do |sgn,sg|
  sg["security_group_rules"].each do |rule|
    case rule["direction"]
    when "ingress"
      ingress<<rule["id"]
    when "egress"
      egress<<rule["id"]
    end
  end
end
if ingress.empty?
  puts "No ingress rules, creating"
  rules=post_json("https://network.compute.sbg-1.runabove.io/v2.0/security-group-rules",token,'{"security_group_rule":{"direction":"ingress","ethertype":"IPv4","security_group_id":"%{id}"}}' % [id: kbrw_sg])
  rules.each do |r,rule|
    if ! rule["id"]
      raise rule["message"]
    else
      puts "Ipv4 rules created"
    end
  end
  rules=post_json("https://network.compute.sbg-1.runabove.io/v2.0/security-group-rules",token,'{"security_group_rule":{"direction":"ingress","ethertype":"IPv6","security_group_id":"%{id}"}}' % [id: kbrw_sg])
  rules.each do |r,rule|
    if ! rule["id"]
      raise rule["message"]
    else
      puts "Ipv6 rules created"
    end
  end
else
  puts "Ingress rules exist, considering they are ok"
end

