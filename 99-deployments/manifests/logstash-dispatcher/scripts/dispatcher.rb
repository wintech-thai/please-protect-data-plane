require 'time'
require 'date'
require 'dalli'
require 'net/http'
require "json"
require 'securerandom'
require 'ipaddr'
require 'csv'
require 'nokogiri'
require 'redis'

def register(params)
    $stdout.sync = true

    redis_host = ENV['REDIS_HOST'] || 'localhost'

    $redis = Redis.new(
        host: redis_host,
        port: 6379
    )
end

def populate_ts_aggregate(event)
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
        ts: Time.now.to_i
    }

    begin
        jsonStr = payload.to_json
        puts("DEBUG : Publishing --> #{jsonStr}")

        $redis.xadd(
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
    event.set('cust_ts_start_dispatched', Time.now.to_i)
    event.set('cust_pod_name_dispatcher', ENV["POD_NAME"])

    line = event.get('message')

    publish_geoip_attack_map(event)

    event.set('cust_ts_done_dispatched', Time.now.to_i)
    return [event]
end
