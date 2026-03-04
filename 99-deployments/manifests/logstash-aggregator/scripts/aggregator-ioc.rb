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

def connect_redis()
    redisHost = ENV["REDIS_HOST"]
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
    @redisObj = connect_redis()
end

def populate_ts_aggregate(event)
end

def set_cache_key_value(cache, aggrKey, hour, value)
  cache.set(aggrKey, value)
  cache.expire(aggrKey, 3600 * hour)
end

def filter(event)
    populate_ts_aggregate(event)
    event.set('cust_ts_start_aggregated', Time.now.to_i)
    event.set('cust_pod_name_aggregator', ENV["POD_NAME"])

    line = event.get('message')

    dataSet = event.get('[event][dataset]')
    srcIp = event.get('[source][ip]')
    dstIp = event.get('[destination][ip]')
    dnsQuestionDomain = event.get('[dns][question][name]')
    sslServerName = event.get('[zeek][ssl][server][name]')
    httpDomain = event.get('[url][domain]')
    fileHashSha256 = event.get('[file][hash][sha256]')
    fileHashMD5 = event.get('[file][hash][md5]')
    fileHashSha1 = event.get('[file][hash][sha1]')

    if srcIp && !srcIp.empty?
        iocType = 'SourceIP'
        iocCacheKeySeen = "IOC_SEEN!!#{iocType}!!#{dataSet}!!#{srcIp}"
        set_cache_key_value(@redisObj, iocCacheKeySeen, 30, Time.now.to_i)
    end

    if dstIp && !dstIp.empty?
        iocType = 'DestinationIP'
        iocCacheKeySeen = "IOC_SEEN!!#{iocType}!!#{dataSet}!!#{dstIp}"
        set_cache_key_value(@redisObj, iocCacheKeySeen, 30, Time.now.to_i)
    end

    if dnsQuestionDomain && !dnsQuestionDomain.empty?
        iocType = 'Domain'
        iocCacheKeySeen = "IOC_SEEN!!#{iocType}!!#{dataSet}!!#{dnsQuestionDomain}"
        set_cache_key_value(@redisObj, iocCacheKeySeen, 30, Time.now.to_i)
    end

    if sslServerName && !sslServerName.empty?
        iocType = 'Domain'
        iocCacheKeySeen = "IOC_SEEN!!#{iocType}!!#{dataSet}!!#{sslServerName}"
        set_cache_key_value(@redisObj, iocCacheKeySeen, 30, Time.now.to_i)
    end

    if httpDomain && !httpDomain.empty?
        iocType = 'Domain'
        iocCacheKeySeen = "IOC_SEEN!!#{iocType}!!#{dataSet}!!#{httpDomain}"
        set_cache_key_value(@redisObj, iocCacheKeySeen, 30, Time.now.to_i)
    end

    if fileHashSha256 && !fileHashSha256.empty?
        iocType = 'FileHashSha256'
        iocCacheKeySeen = "IOC_SEEN!!#{iocType}!!#{dataSet}!!#{fileHashSha256}"
        set_cache_key_value(@redisObj, iocCacheKeySeen, 30, Time.now.to_i)
    end

    if fileHashMD5 && !fileHashMD5.empty?
        iocType = 'FileHashMD5'
        iocCacheKeySeen = "IOC_SEEN!!#{iocType}!!#{dataSet}!!#{fileHashMD5}"
        set_cache_key_value(@redisObj, iocCacheKeySeen, 30, Time.now.to_i)
    end

    event.set('cust_ts_done_aggregated', Time.now.to_i)
    return [event]
end
