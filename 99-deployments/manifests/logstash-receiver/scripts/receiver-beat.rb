require 'time'
require 'date'
require 'dalli'
require 'net/http'
require "json"
require 'securerandom'
require 'ipaddr'
require 'csv'
require 'nokogiri'

def register(params)
    $stdout.sync = true
end

def populate_ts_aggregate(event)
    dtm = DateTime.now
    dtm += Rational('7/24') # Thailand timezone +7
  
    event.set('cust_ts_yyyy', dtm.year)
    event.set('cust_ts_mm', dtm.mon.to_s.rjust(2,'0'))
    event.set('cust_ts_dd', dtm.mday.to_s.rjust(2,'0'))
    event.set('cust_ts_hh', dtm.hour.to_s.rjust(2,'0'))
    event.set('cust_ts_wd', dtm.wday.to_s.rjust(2,'0'))
end

def filter(event)
    populate_ts_aggregate(event)
    event.set('cust_ts_start_received', Time.now.to_i)
    event.set('cust_pod_name_receiver', ENV["POD_NAME"])
    event.set('cust_category', 'file_beat')

    line = event.get('message')

    event.set('cust_ts_done_received', Time.now.to_i)
    return [event]
end
