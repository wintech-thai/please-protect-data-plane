require 'time'
require 'date'
require 'dalli'
require 'net/http'
require "json"
require 'securerandom'
require 'ipaddr'
require 'nokogiri'
require 'redis'

def connect_redis()
    redisHost = 'redis-master.redis.svc.cluster.local'
    begin
        r = Redis.new(
          :host => redisHost,
          :port => 6379,
        )

        client_ping = r.ping
        if (client_ping)
          puts("INFO : Connected to Redis [#{redisHost}]")
        else
          raise 'Ping failed!!!'
        end
      rescue => e
        puts("ERROR: #{e}")
        exit 100
    end

    return r
end

def register(params)
    $stdout.sync = true

    @cidr_map = Hash.new()
    @redisObj = connect_redis()

    @cacheLoadedConfig = Hash.new()
    @cacheLoadedConfig['ip_address_map'] = { 'cache_ttl_sec' => 180, 'last_run_epoch_sec' => 0 }
end

def populate_ts_aggregate(event)
end

def load_ip_map_zone(orgId, environment)
    puts("DEBUG : Start loading IP --> Zone mapping from Redis...\n")
    # populate @cidr_map here...
    # var key = $"Subnet:{orgId}:{environment}:{cidr}";

    rec_map = Hash.new()
    cnt = 0

    @redisObj.scan_each(match: "Subnet:#{orgId}:#{environment}:*") do |key|
        zone = @redisObj.get(key)

        keyword, org, env, cidr = key.split(":")
        rec_map[cidr] = [zone, IPAddr.new(cidr)]

        cnt = cnt + 1

        puts("DEBUG : Loading IP map (#{env}/#{org}) [#{cidr}] [#{zone}]\n")
    end

    @cidr_map = rec_map
    puts("DEBUG : Done loading [#{cnt}] IP --> Zone mapping from Redis\n")
end

def load_cache(orgId, cacheConfigKey)
    currentEpochSec = Time.now.to_i

    cacheTtlSec = @cacheLoadedConfig[cacheConfigKey]['cache_ttl_sec']
    lastRunSec = @cacheLoadedConfig[cacheConfigKey]['last_run_epoch_sec']

    if (currentEpochSec - lastRunSec > cacheTtlSec)
        if (cacheConfigKey == 'ip_address_map')
            load_ip_map_zone('default', 'Production') # TODO: make env dynamic later
            @cacheLoadedConfig[cacheConfigKey]['last_run_epoch_sec'] = Time.now.to_i
        end
    end
end

def is_ip?(ip)
    !!IPAddr.new(ip) rescue false
end

def populate_zone(event, from_field_name, to_field_name)

    ip = event.get(from_field_name)
    if ip.nil? or ip == ''
        return
    end

    if !is_ip?(ip)
        puts("DEBUG : IP [#{ip}] is not valid\n")
        return
    end

    net2 = IPAddr.new(ip)
    @cidr_map.each do |cidr, zoneArr|
        zone = zoneArr[0]
        cidrNet = zoneArr[1]
        
        if (cidrNet.include?(net2))
            event.set(to_field_name, zone)
            return
        end
    end

    event.set(to_field_name, '==unknown==')
end

def public_ip?(ip)
    return false if ip.nil? || ip.to_s.strip.empty?

    begin
        addr = IPAddr.new(ip)

        # IPv4 checks
        if addr.ipv4?
            return false if addr.private?
            return false if addr.loopback?
            return false if addr.link_local?

            # multicast
            return false if IPAddr.new('224.0.0.0/4').include?(addr)

            # reserved
            return false if IPAddr.new('0.0.0.0/8').include?(addr)
            return false if IPAddr.new('100.64.0.0/10').include?(addr)
            return false if IPAddr.new('169.254.0.0/16').include?(addr)
            return false if IPAddr.new('240.0.0.0/4').include?(addr)

            return true
        end

        # IPv6 checks
        if addr.ipv6?
            return false if addr.loopback?
            return false if addr.link_local?

            # Unique local address (fc00::/7)
            return false if IPAddr.new('fc00::/7').include?(addr)

            # Multicast (ff00::/8)
            return false if IPAddr.new('ff00::/8').include?(addr)

            # Unspecified (::/128)
            return false if IPAddr.new('::/128').include?(addr)

            return true
        end

        false
    rescue
        false
    end
end

def publish_geoip_attack_map(event)
    source_ip   = event.get('[source][address]')
    dest_ip     = event.get('[destination][address]')

    source_port = event.get('[source][port]')
    dest_port   = event.get('[destination][port]')

    dataset     = event.get('[event][dataset]')

    source_lat  = event.get('[source][geoip][latitude]')
    source_long = event.get('[source][geoip][longitude]')

    dest_lat    = event.get('[destination][geoip][latitude]')
    dest_long   = event.get('[destination][geoip][longitude]')

    source_country = event.get('[source][geoip][country_name]')
    dest_country = event.get('[destination][geoip][country_name]')

    # publish เฉพาะเมื่อ source หรือ destination เป็น public IP
    return unless public_ip?(source_ip) || public_ip?(dest_ip)

    payload = {
        source_ip: source_ip,
        dest_ip: dest_ip,
        source_port: source_port,
        dest_port: dest_port,
        dataset: dataset,
        source_lat: source_lat,
        source_long: source_long,
        dest_lat: dest_lat,
        dest_long: dest_long,
        source_country: source_country,
        dest_country: dest_country,
        ts: Time.now.to_i
    }

    begin
        jsonStr = payload.to_json
        puts("DEBUG : Publishing --> #{jsonStr}")

        @redisObj.xadd(
            'geoip-attack-map',
            '*',
            {
                'data' => jsonStr
            }
        )
    rescue => e
        puts "Redis stream publish error: #{e}"
    end
end

def filter(event)
    populate_ts_aggregate(event)
    event.set('cust_ts_start_transformed', Time.now.to_i)
    event.set('cust_pod_name_transformer', ENV["POD_NAME"])

    load_cache('default', 'ip_address_map')

    populate_zone(event, '[source][ip]', '[source][network_zone]')
    populate_zone(event, '[destination][ip]', '[destination][network_zone]')

    publish_geoip_attack_map(event)

    event.set('cust_ts_done_transformed', Time.now.to_i)
    return [event]
end
