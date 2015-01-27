#!/usr/bin/ruby

require 'json'
require 'curb'
require 'getopt/std'

opt = Getopt::Std.getopts("s:t:")
#site_code = "bhs-1"
site_code = "sbg-1"
ext_net = nil
company_network = nil
company_vmipv4 = nil
company_vmipv6 = nil
company_sg = nil
company_sg_name = "company_sg"
#ra.p8.s ra.intel.ha.l ra.intel.ssd.xl1 ra.intel.ssd.xl4 ra.p8.2xl ra.intel.ha.s ra.intel.ssd.xl2 ra.intel.ssd.xl3 ra.intel.ha.
company_flavor = "ra.intel.ha.s" 
company_flavor_url = nil
company_image = "VM-ready"
company_image_url = nil
company_key_name = "key_name"
company_server_num = []
company_new_server = nil
ingress = []
egress = []

company_runaboveid = "e...9"

def get_token (url,payload)
    c = Curl::Easy.http_post(url,payload) do |curl|
      # curl.verbose = true
      curl.headers['Content-Type'] = 'application/json'
    end
    return JSON.parse(c.body_str)["access"]["token"]["id"]
end 

token=get_token('https://auth.runabove.io/v2.0/tokens', '{"auth": {"tenantName": "12345678", "passwordCredentials":{"username": "user@company.com", "password": "password"}}}')


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
    #curl.verbose = true
    curl.headers["X-Auth-Token"] = token
    curl.headers["Content-Type"] = ["application/json"]
    curl.headers["Accept"] = "application/json"
    curl.http_post(options)
    return JSON.parse(curl.body_str)
  end
end

def post_json2 (url,token,payload)
  c = Curl::Easy.http_post(url, payload) do |curl|
    # curl.verbose = true
    curl.headers['X-Auth-Token'] = token
    curl.headers['Accept']       = 'application/json'
    curl.headers['Content-Type'] = 'application/json'
  end
  return JSON.parse(c.body_str)
end

def next_id(all_ids, used_ids)
  trous = all_ids - used_ids
  id = nil
  if (trous.size() > 0)
    id=trous.first
  else
    id=used_ids.max + 1
  end
  return sprintf "%02d", id
end

puts "# Network Creation #"
puts " Get network info for company_private"
networks=get_info("https://network.compute.#{site_code}.runabove.io/v2.0/networks",token)

networks["networks"].each do |net|
  if net["name"] == "Ext-Net"
    ext_net = net["id"]
  end
  if net["name"] == "company_private"
    if ! company_network.nil?
      raise 'Two or more networks named company_private'
    end
    company_network = net["id"]
  end
end

if company_network.nil?
  puts " Network not found, creating ..."
  networks=post_json("https://network.compute.#{site_code}.runabove.io/v2.0/networks",token,'{"network":{"name":"company_private","admin_state_up":true}}')
  networks.each do |netw,net|
    if net["name"] == "company_private"
      company_network = net["id"]
      puts " Network created"
    else
      raise " Network creation failed : #{net['message']}" 
    end
  end
end


if company_network
  puts " Network exist : #{company_network}"
  puts " Searching for existing Subnet"
  #{"subnets": [{"name": "", "enable_dhcp": true, "network_id": "f5cc56db-db25-4488-8371-c507951b2631", "tenant_id": "b6bc4198c6b54b3abe083200d69790cb", "dns_nameservers": ["213.186.33.99"], "allocation_pools": [{"start": "92.222.64.1", "end": "92.222.95.254"}], "host_routes": [], "ip_version": 4, "gateway_ip": "92.222.53.226", "cidr": "92.222.64.0/19", "id": "2c56a226-e78b-4268-b3d4-96e61e4fc0fe"}, {"name": "vm", "enable_dhcp": false, "network_id": "d24612cd-4e49-408e-9b07-bfae104d6530", "tenant_id": "ec58c087117441159c74e74c55d87f29", "dns_nameservers": ["8.8.8.8"], "allocation_pools": [{"start": "10.0.255.20", "end": "10.0.255.120"}], "host_routes": [{"nexthop": "10.0.255.1", "destination": "172.16.0.0/12"}], "ip_version": 4, "gateway_ip": "10.0.255.1", "cidr": "10.0.255.0/24", "id": "f0b10c59-bd05-460c-953f-eddd31d2de96"}, {"name": "vm ipv6", "enable_dhcp": false, "network_id": "d24612cd-4e49-408e-9b07-bfae104d6530", "tenant_id": "ec58c087117441159c74e74c55d87f29", "dns_nameservers": [], "allocation_pools": [{"start": "2001:41d0:9a:b000::2", "end": "2001:41d0:9a:b000:ffff:ffff:ffff:fffe"}], "host_routes": [], "ip_version": 6, "gateway_ip": "2001:41d0:9a:b000::1", "cidr": "2001:41d0:9a:b000::/64", "id": "f96f70f3-07fa-44cb-9a52-9fb1d552410c"}]}
  subnets=get_info("https://network.compute.#{site_code}.runabove.io/v2.0/subnets",token)
  subnets["subnets"].each do |net|
    #puts net
    case net["name"]
    when "company_vmipv4"
      if net["network_id"] == company_network
        puts ' Subnet company_ipv4 for network company_network already exist'
        company_vmipv4 = net["id"]
      end
    when "company_vmipv6"
      if net["network_id"] == company_network
        puts ' Subnet company_ipv6 for network company_network already exist'
        company_vmipv6 = net["id"]
      end
    end
  end
end

if company_vmipv4.nil?
  puts " Ipv4 subnet not found"
  puts " Ipv4 subnet creating"
  networks=post_json("https://network.compute.#{site_code}.runabove.io/v2.0/subnets",token,'{"subnet":{"name":"company_vmipv4","ip_version":4,"cidr":"10.0.248.0/21","enable_dhcp":true,"allocation_pools": [{"start": "10.0.255.2", "end": "10.0.255.254"}],"host_routes":[{"nexthop":"10.0.255.1","destination":"172.16.0.0/12"}],"network_id":"%{id}"}}' % [id: company_network])
  networks.each do |netw,net|
    if net["name"] == "company_vmipv4"
      company_vmipv4 = net["id"]
      puts " Subnet created"
    else
      raise " Subnet creation failed : #{net['message']}"
    end
  end
end

if company_vmipv6.nil?
  puts " Ipv6 subnet not found"
  puts " Ipv6 subnet creating"
  networks=post_json("https://network.compute.#{site_code}.runabove.io/v2.0/subnets",token,'{"subnet":{"name":"company_vmipv6","ip_version":6,"cidr":"2001:41d0:9a:aaa1::/64","enable_dhcp":true,"allocation_pools": [{"start": "2001:41d0:9a:aaa1:ffff::2", "end": "2001:41d0:9a:aaa1:ffff::ffff"}],"host_routes": [{"nexthop":"2001:41d0:9a:aaa1:ffff::0","destination":"2001:41d0:9a:a01::/64"},{"nexthop":"2001:41d0:9a:aaa1:ffff::0","destination":"2001:41d0:9a:a04::/64"}],"network_id":"%{id}"}}' % [id: company_network])
  networks.each do |netw,net|
    if net["name"] == "company_vmipv6"
      company_vmipv6 = net["id"]
      puts " Subnet created"
    else
      raise " Subnet6 creation failed #{net['message']}"
    end
  end
end

sg=get_info("https://network.compute.#{site_code}.runabove.io/v2.0/security-groups",token)
sg.each do |secw,secg|
  secg.each do |sec|
    if sec["name"] == company_sg_name
      if ! company_sg.nil?
        raise ' Two or more sg named company_sg'
      end
      company_sg = sec["id"]
    end
  end
end

if company_sg.nil?
  puts "Creating Security Group company_sg"
  sg=post_json("https://network.compute.#{site_code}.runabove.io/v2.0/security-groups",token,'{"security_group":{"name":"company_sg","description":"company sg"}}')
  sg.each do |secg,sec|
    if sec["name"] == "company_sg"
      company_sg = sec["id"]
      puts " Security Group created"
    else
      raise " SG creation failed : #{sec['message']}"
    end
  end
else
  puts " Security Group company_sg already exist"
end

sglist=get_info("https://network.compute.#{site_code}.runabove.io/v2.0/security-groups/#{company_sg}",token)
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
  puts " No ingress rules, creating"
  rules=post_json("https://network.compute.#{site_code}.runabove.io/v2.0/security-group-rules",token,'{"security_group_rule":{"direction":"ingress","ethertype":"IPv4","security_group_id":"%{id}"}}' % [id: company_sg])
  rules.each do |r,rule|
    if ! rule["id"]
      raise " Rule creation failed : #{rule['message']}"
    else
      puts " Ipv4 rules created"
    end
  end
  rules=post_json("https://network.compute.#{site_code}.runabove.io/v2.0/security-group-rules",token,'{"security_group_rule":{"direction":"ingress","ethertype":"IPv6","security_group_id":"%{id}"}}' % [id: company_sg])
  rules.each do |r,rule|
    if ! rule["id"]
      raise " Rule6 creation failed : #{rule['message']}"
    else
      puts " Ipv6 rules created"
    end
  end
else
  puts " Ingress rules exist, considering they are ok"
end

puts "\n# New host creation #"
puts " Retrieving flavor link"
fl=get_info("https://compute.#{site_code}.runabove.io/v2/#{company_runaboveid}/flavors",token)
fl["flavors"].each do |flavor|
  if flavor["name"] == company_flavor
    company_flavor_url = flavor["links"][0]["href"].gsub("http:","https:")
  end
end
if company_flavor_url.nil?
  raise ' Flavor url not found' 
else
  puts " Flavor url : #{company_flavor_url}"
end
puts " Retrieving image link"
im=get_info("https://compute.#{site_code}.runabove.io/v2/#{company_runaboveid}/images",token)
im["images"].each do |image|
  if image["name"] == company_image 
    company_image_url = image["links"][0]["href"].gsub("http:","https:")
  end
end
if company_image_url.nil?
  raise ' Image url not found' 
else
  puts " Image url : #{company_image_url}"
end
puts " Get next server name"

srv=get_info("https://compute.#{site_code}.runabove.io/v2/#{company_runaboveid}/servers",token)
srv["servers"].each do |server|
  if server["name"] =~ /^runabove*/
    company_server_num << server["name"].split(/runabove/,2).last.to_i
  end
end
end_net = ""
if company_server_num.empty?
  puts " First node"
  company_new_server = "runabove01.company.com"
  end_net = "01"
else
  all = (1..99).to_a
  cur = company_server_num
  end_net = next_id(all, company_server_num)
  company_new_server = "runabove" + next_id(all, company_server_num) + ".companye.com"
  puts " New node name :" + company_new_server
end

require "base64"
puts " Generate user data"
puts "  Generate network conf"
net_conf=' auto lo eth0 eth1
       iface lo inet loopback

       iface eth0 inet dhcp
       iface eth1 inet static
        address 10.0.0.%{end_net}
        netmask 255.255.248.0

       iface eth1 inet6 static
        address 2001:ffff::%{end_net}
        netmask 64

' % [end_net: end_net]

net_conf64=Base64.strict_encode64(net_conf)

user_data='#cloud-config
package_upgrade: true
write_files:
  - path: /etc/company_cloudinit
    content: |
      OK
    owner: "root"
    permission : "0600"
  - path: /etc/network/interfaces
    owner: "root"
    content: |
      %{netconf}
    permission: "0644"
power_state:
  mode: reboot
  message: Cloud-init first reboot
  timeout: 30
# Capture all subprocess output into a logfile
# Useful for troubleshooting cloud-init issues
output: {all: "| tee -a /var/log/cloud-init-output.log"}' % [nodename: company_new_server, netconf: net_conf]

user_data64 = Base64.strict_encode64(user_data)
json_string='{"server":{"name":"%{name}","imageRef":"%{imageref}","flavorRef":"%{flavorref}","networks":[{"uuid":"%{net1}"},{"uuid":"%{net2}"}],"security_groups":[{"name":"%{sg}"},{"name":"%{sg}"}],"key_name":"%{keyname}","user_data":"%{user_data64}"}}' % [name: company_new_server, imageref: company_image_url, flavorref: company_flavor_url, net1: ext_net, net2: company_network, sg:company_sg_name, keyname: company_key_name,user_data64: user_data64]
new_srv=post_json2("https://compute.#{site_code}.runabove.io/v2/#{company_runaboveid}/servers?#{company_sg_name},,BHS-1",token,json_string)
new_srv.each do |srv,info|
  if ! info["adminPass"]
    raise " Server creation failed : #{info['message']}"
  else
    puts " Server is beeing created: admin pass #{info['adminPass']}"
  end
end
