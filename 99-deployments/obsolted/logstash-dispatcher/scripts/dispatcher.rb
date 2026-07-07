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
end

def populate_ts_aggregate(event)
end

def filter(event)
    populate_ts_aggregate(event)
    event.set('cust_ts_start_dispatched', Time.now.to_i)
    event.set('cust_pod_name_dispatcher', ENV["POD_NAME"])

    line = event.get('message')

    event.set('cust_ts_done_dispatched', Time.now.to_i)
    return [event]
end
