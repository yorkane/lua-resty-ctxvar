--[[
License MIT
]]
local nvar, concat, ngxreq, nphase, hash = ngx.var, table.concat, ngx.req, ngx.get_phase
local find, sub, byte, sreverse = string.find, string.sub, string.byte, string.reverse
local setmetatable, type, rawset = setmetatable, type, rawset
local ngsub = ngx.re.gsub

local ngx_var = {
    arg_name = "", -- argument name in the request line
    args = "", -- arguments in the request line
    binary_remote_addr = "", -- client address in a binary form, value’s length is always 4 bytes for IPv4 addresses or 16 bytes for IPv6 addresses
    body_bytes_sent = "", -- number of bytes sent to a client, not counting the response header; this variable is compatible with the “%B” parameter of the mod_log_config Apache module
    bytes_sent = "", -- number of bytes sent to a client (1.3.8, 1.2.5)
    connection = "", -- connection serial number (1.3.8, 1.2.5)
    connection_requests = "", -- current number of requests made through a connection (1.3.8, 1.2.5)
    content_length = "", -- “Content-Length” request header field
    content_type = "", -- “Content-Type” request header field
    cookie_name = "", -- the name cookie
    document_root = "", -- root or alias directive’s value for the current request
    document_uri = "", -- same as $uri
    host = "", -- in this order of precedence: host name from the request line, or host name from the “Host” request header field, or the server name matching a request
    hostname = "", -- host name
    http_name = "", -- arbitrary request header field; the last part of a variable name is the field name converted to lower case with dashes replaced by underscores
    https = "", -- “on” if connection operates in SSL mode, or an empty string otherwise
    is_args = "", -- “?” if a request line has arguments, or an empty string otherwise
    limit_rate = "", -- setting this variable enables response rate limiting; see limit_rate
    msec = "", -- current time in seconds with the milliseconds resolution (1.3.9, 1.2.6)
    nginx_version = "", -- nginx version
    pid = 1234, -- PID of the worker process
    pipe = "", -- “p” if request was pipelined, “.” otherwise (1.3.12, 1.2.7)
    proxy_protocol_addr = "", -- client address from the PROXY protocol header (1.5.12). The PROXY protocol must be previously enabled by setting the proxy_protocol parameter in the listen directive.
    proxy_protocol_port = "", -- client port from the PROXY protocol header (1.11.0). The PROXY protocol must be previously enabled by setting the proxy_protocol parameter in the listen directive.
    proxy_protocol_server_addr = "", -- server address from the PROXY protocol header (1.17.6). The PROXY protocol must be previously enabled by setting the proxy_protocol parameter in the listen directive.
    proxy_protocol_server_port = "", -- server port from the PROXY protocol header (1.17.6). The PROXY protocol must be previously enabled by setting the proxy_protocol parameter in the listen directive.
    query_string = "", -- same as $args
    realpath_root = "", -- an absolute pathname corresponding to the root or alias directive’s value for the current request, with all symbolic links resolved to real paths
    remote_addr = "127.0.0.1", -- client address
    remote_port = "", -- client port
    remote_user = "", -- user name supplied with the Basic authentication
    request = "", -- full original request line
    request_body = "", -- request body. The variable’s value is made available in locations processed by the proxy_pass, fastcgi_pass, uwsgi_pass, and scgi_pass directives when the request body was read to a memory buffer.
    request_body_file = "", -- name of a temporary file with the request body. At the end of processing, the file needs to be removed. To always write the request body to a file, client_body_in_file_only needs to be enabled. When the name of a temporary file is passed in a proxied request or in a request to a FastCGI/uwsgi/SCGI server, passing the request body should be disabled by the proxy_pass_request_body off, fastcgi_pass_request_body off, uwsgi_pass_request_body off, or scgi_pass_request_body off directives, respectively.
    request_completion = "", -- “OK” if a request has completed, or an empty string otherwise
    request_filename = "", -- file path for the current request, based on the root or alias directives, and the request URI
    request_id = '7ced51898a63d0d25ad92b953bd20af5', -- unique request identifier generated from 16 random bytes, in hexadecimal (1.11.0)
    request_length = "", -- request length (including request line, header, and request body) (1.3.12, 1.2.7)
    request_method = "", -- request method, usually “GET” or “POST”
    request_time = "", -- request processing time in seconds with a milliseconds resolution (1.3.9, 1.2.6); time elapsed since the first bytes were read from the client
    request_uri = "/path/file", -- full original request URI (with arguments)
    scheme = "", -- request scheme, “http” or “https”
    sent_http_name = "", -- arbitrary response header field; the last part of a variable name is the field name converted to lower case with dashes replaced by underscores
    sent_trailer_name = "", -- arbitrary field sent at the end of the response (1.13.2); the last part of a variable name is the field name converted to lower case with dashes replaced by underscores
    server_addr = "", -- an address of the server which accepted a request. Computing a value of this variable usually requires one system call. To avoid a system call, the listen directives must specify addresses and use the bind parameter.
    server_name = "", -- name of the server which accepted a request
    server_port = "", -- port of the server which accepted a request
    server_protocol = "", -- request protocol, usually “HTTP/1.0”, “HTTP/1.1”, or “HTTP/2.0”
    status = "", -- response status (1.3.2, 1.2.2)
    tcpinfo_rtt = 0,
    tcpinfo_rttvar = 0,
    tcpinfo_snd_cwnd = 0,
    tcpinfo_rcv_space = "", -- information about the client TCP connection; available on systems that support the TCP_INFO socket option
    time_iso8601 = "", -- local time in the ISO 8601 standard format (1.3.12, 1.2.7)
    time_local = "", -- local time in the Common Log Format (1.3.12, 1.2.7)
    uri = "/" --current URI in request, normalized. The value of $uri may change during request processing
}
---@class resty.ctxvar
---@field request_header table<string,string> @ keep reqeust header
---@field resp_header table<string,string> @ keep response header
---@field ip string @ as xxx.xxx.xxx.xxx
---@field request_body string @ any phase could inject the body for next phases
---@field response_body string @ any phase could inject the body for next phases
---@field is_json boolean @ indicate current request is asking for JSON response
---@field is_timer boolean @ indicate current request is initiated from timer phase (usually by system call)
---@field is_static string @ indicate current request is asking for static content
local _M = {
    is_timer = true, -- just leave a key to indicate current request is from timer,
    is_static = false,
    response_body = "",
    request_header = {},
    is_json = false,
    ___is_ctx_env = true,
    is_query_changed = false,
    is_uri_changed = false,
    resp_header = {},
    var = ngx_var,
    ip = "127.0.0.1", -- could be remote_addr
    uri_args = {},
    file_format = "html",
    -- request_path = "/path",
    -- phase = "timer",
}

local valid_phase = {
    set = true,
    rewrite = true,
    balancer = true,
    access = true,
    content = true,
    header_filter = true,
    body_filter = true,
    log = true
}

function _M.get_file_suffix(url)
    local inx = find(url, "?", 1, true)
    if inx then
        url = sub(url, 1, inx - 1)
    end
    local len = #url
    if len < 2 then
        return nil
    end
    if len < 7 then
        len = 7
    end
    local c1, c2, c3, c4, c5, c6 = byte(url, len - 6, len)
    --logs(url, byte(url, len - 6, len))
    -- char(46) = `.`
    if c1 == 46 then
        return sub(url, len - 5, len)
    end
    if c2 == 46 then
        return sub(url, len - 4, len)
    end
    if c3 == 46 then
        return sub(url, len - 3, len)
    end
    if c4 == 46 then
        return sub(url, len - 2, len)
    end
    if c5 == 46 then
        return sub(url, len - 1, len)
    end
    if c6 == 46 then
        return sub(url, len, len)
    end
    return ""
end

local ctvmt = {
    __index = function(self, key)
        local data
        if key == "request_body" then
            data = self.var.request_body
			rawset(self, key, data)
			return data
        elseif key == "request_header" then
            data = ngx.req.get_headers()
            -- rawset(self, key, data)
            return data
        elseif key == "uri_args" then
            data = self.var.uri_args
            rawset(self, key, data)
        elseif key == "uri" then
            rawset(self, key, self.var.uri)
        elseif key == "ip" then
            local header = self.request_header
			local data = header["remoteip"] or header["X-real-ip"] or header["x-forwarded-for"] or self.var.remote_addr
			rawset(self, key, data)
			return data
        elseif key == "request_body" then
            ngx.req.read_body()
            data = ngx.req.get_body_data() or ""
            rawset(self, key, data)
            return data
        elseif key == "file_format" then
            data = _M.get_file_suffix(self.var.request_uri)
            rawset(self, key, data)
            return data
        elseif key == "uri_args" then
            data = ngx.req.get_uri_args()
            rawset(self, key, data)
            return data
        elseif key == "post_args" then
            ngx.req.read_body()
            data = ngx.req.get_post_args()
            rawset(self, key, data)
			return data
		elseif key == 'is_json' then
			data = self.var.content_type
			if data and find(data, 'json', 1, true) then
				rawset(self, key, true)
			else
				rawset(self, key, false)
			end
		else
			return data
        end
    end
}

local mt = {
    __metatable = "No access to ngx-system-context metatable", --prevent from metable modifying
    __newindex = function(self, key)
        return nil, "No modification to ngx-system-context variable"
    end,
    __index = function(self, key)
        local data = rawget(self, key)
        if data ~= nil then
            return data
        end
        if key == "is_timer" then
            data = ngx.get_phase()
            if data == "timer" then
                rawset(self, "is_timer", true)
                return true
            else
                rawset(self, "is_timer", false)
                return false
            end
        end
        if self.is_timer then
            return ngx_var[key]
        elseif key == "is_timer" then
            data = ngx.get_phase()
            if data == "timer" then
                rawset(self, "is_timer", true)
                return true
            else
                rawset(self, "is_timer", false)
                return false
            end
        elseif key == "host" then
            data = nvar.host
            rawset(self, key, data)
            return data
        elseif key == "request_uri" then
            data = nvar.request_uri
            rawset(self, key, data)
            return data
        elseif key == "request_path" then
            data = self.request_uri
            local inx = find(data, "?", 2, true)
            if inx then
                rawset(self, "query_string", sub(data, inx + 1, -1))
                data = sub(data, 1, inx - 1)
            else
                rawset(self, "query_string", "")
            end
            rawset(self, key, data)
            return data
        elseif key == "query_string" then
            data = self.request_uri
            local inx = find(data, "?", 2, true)
            if inx then
                rawset(self, "request_path", sub(data, 1, inx - 1))
                data = sub(data, inx + 1, -1)
            else
                rawset(self, "request_path", data)
                data = ""
            end
            rawset(self, key, data)
            return data
        elseif key == "url" then
            data = self.request_uri
            local host, port, schema, port_str = self.host, self.server_port, self.schema
            if port == "443" and schema == "https" then
                port_str = ""
            elseif port == "80" and schema == "http" then
                port_str = ""
            else
                port_str = ":" .. port
            end
            data = schema .. "://" .. host .. port_str .. data
            rawset(self, key, data)
            return data
        elseif key == "uri" then
            data = self.request_uri
            local inx = find(data, "?", 2, true)
            if inx then
                data = sub(data, 1, inx - 1)
            end
            rawset(self, key, data)
            return data
        elseif key == "port" or key == "server_port" then
            data = nvar.server_port
            rawset(self, key, data)
            return data
        elseif key == "method" or key == "request_method" then
            data = ngx.req.get_method()
            rawset(self, key, data)
            return data
        elseif key == "phase" then
            data = ngx.get_phase()
            return data
        elseif key == "remote_addr" then
            data = nvar.remote_addr
            rawset(self, key, data)
            return data
        elseif key == "schema" then
            data = nvar.schema
            rawset(self, key, data)
            return data
		elseif key == "request_id" then
			return nvar[key]
        else
            data = nvar[key] or ""
            rawset(self, key, data) -- prevent costy empty ngx.var visit
            return data
        end
    end
}

---new boost performance for ngx.ctx._env, and avoid phase call failures, and always return string
---@return resty.ctxvar
function _M.new(tb)
    if not tb then
        tb = ngx.ctx._env
        if not tb then
            tb = table.new(0, 17)
            tb.resp_header = table.new(0, 17)
            ngx.ctx._env = tb
        end
    end
    if type(tb) ~= "table" then
        return nil, "table type required"
    end
    if not tb.___is_ctx_env then
        tb.___is_ctx_env = true
        if not tb.var then
            tb.var = table.new(0, 17)
            setmetatable(tb.var, mt)
        end
        setmetatable(tb, ctvmt)
    end
    return tb
end

local timer_ngx = {
    status = 200,
    header = {}
}
setmetatable(timer_ngx, {__index = ngx})

---get_ngx
---@param env system.env
---@return ngx_mock
function _M.get_ngx(env)
    env = _M.new(env)
    if env.is_timer then
        return timer_ngx
    end
    return ngx
end

setmetatable(
    _M,
    {
        __call = function(self, tab)
            return _M.new(tab)
        end
    }
)

local dump = require("resty.klib.dump").global()
function _M.main()
    local ctv = _M.new()
    local empty_tb = {}
    -- logs(ctv)
	for key, val in pairs(ngx_var) do
		if key ~= 'request_id' then
			local v1, v2 = ngx.var[key], ctv.var[key]
        	if v1 ~= v2 and (v2 ~= "" and v2 ~= empty_tb) then
				logs(key, v2, v1, ngx.var['request_id'])
				error(key .. " with ngx.var not match in ctxvar")
			-- logs(key, type(v1), type(v2))
        	end
		end
    end
end

function _M.test()
	local c = _M.new()
	local t = c.ip
	c.request_header['sss'] = 'ss1'
	-- ngx.say(t)
	-- c.ip = 222
	c.response_body = 'sss'
	logs(c, c.var.request_body)
end

return _M
