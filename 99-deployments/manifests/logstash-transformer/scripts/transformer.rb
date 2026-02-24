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
            load_ip_map_zone('default', 'Development') # TODO: make env dynamic later
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

def filter(event)
    populate_ts_aggregate(event)
    event.set('cust_ts_start_transformed', Time.now.to_i)
    event.set('cust_pod_name_transformer', ENV["POD_NAME"])

    load_cache('default', 'ip_address_map')

    populate_zone(event, '[source][ip]', '[source][network_zone]')
    populate_zone(event, '[destination][ip]', '[destination][network_zone]')

    event.set('cust_ts_done_transformed', Time.now.to_i)
    return [event]
end
