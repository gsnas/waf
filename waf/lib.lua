--waf core lib
require("config")

local _rule_cache = {}
local ipmatcher = require("resty.ipmatcher")
local trusted_matcher = nil

-- 初始化函数（在预加载后调用）
local function init_trusted_proxy()
	local raw_rules = get_rule("trusted_proxy.rule") or {}
	local trusted_rules = {}

	for _, line in ipairs(raw_rules) do
		-- 去除前后空格
		line = line:gsub("^%s*(.-)%s*$", "%1")
		-- 跳过空行、-- 开头的注释、# 开头的注释
		if line ~= "" and not line:match("^%-%-") and not line:match("^#") then
			table.insert(trusted_rules, line)
		end
	end

	if #trusted_rules > 0 then
		local matcher, err = ipmatcher.new(trusted_rules)
		if not matcher then
			ngx.log(ngx.ERR, "failed to create trusted proxy matcher: ", err or "unknown")
		else
			trusted_matcher = matcher
			ngx.log(ngx.INFO, "Trusted proxy matcher loaded with ", #trusted_rules, " valid IPv4/IPv6 rules")
		end
	else
		ngx.log(ngx.WARN, "No valid trusted proxy rules found after filtering comments")
	end
end

function is_trusted_proxy(ip)
	if not trusted_matcher then
		return false
	end
	local ok = trusted_matcher:match(ip)
	return ok == true
end

--Get WAF rule
function get_rule(rulefilename)
	-- 1. 首先检查内存缓存中是否已经存在该规则
	if _rule_cache[rulefilename] then
		return _rule_cache[rulefilename]
	end

	-- 2. 如果缓存不存在，则读取文件
	local io = require("io")
	local rule_path = config_rule_dir
	local file_path = rule_path .. "/" .. rulefilename
	local rule_file = io.open(file_path, "r")

	if not rule_file then
		return nil
	end

	local rule_table = {}
	for line in rule_file:lines() do
		line = string.gsub(line, "[\r\n%s]+", "")
		if line ~= "" then
			table.insert(rule_table, line)
		end
	end
	rule_file:close()
	ngx.log(ngx.INFO, "WAF rule updated: ", rulefilename)

	-- 3. 将读取结果写入缓存
	_rule_cache[rulefilename] = rule_table
	return rule_table
end

--Get the client IP
function get_client_ip()
	-- 优先使用常见 CDN 专用 header
	local headers = ngx.req.get_headers()
	local cdn_ips = {
		"cf-connecting-ip", -- Cloudflare
		"true-client-ip", -- Akamai
		"x-real-ip", -- 常见 Nginx 配置
		"ali-cdn-real-ip", -- 阿里云
		"tencent-cdn-real-ip", -- 腾讯云
	}
	for _, header in ipairs(cdn_ips) do
		local ip = headers[header]
		if ip and ip ~= "" then
			ip = ip:gsub("^%s*(.-)%s*$", "%1")
			if not is_trusted_proxy(ip) then
				return ip
			end
		end
	end
	local client_ip = "unknown"
	local xff = ngx.var.http_x_forwarded_for

	if xff then
		-- 从右往左遍历（获取不是信任代理IP的第一个IP）
		-- 如果用户配置了正向代理，拦截正向代理IP（user_ip, proxy_ip, cf_cdn_ip, haproxy_ip remote_addr）
		local ips = {}
		for ip in xff:gmatch("%s*([^,%s]+)") do
			table.insert(ips, ip)
		end
		-- 然后从后往前遍历（最右是最近的代理）
		for i = #ips, 1, -1 do
			local ip = ips[i]:gsub("^%s*(.-)%s*$", "%1")
			if ip ~= "" and not is_trusted_proxy(ip) then
				client_ip = ip
				break
			end
		end
	end

	if client_ip == "unknown" or client_ip == "" then
		client_ip = ngx.var.remote_addr or "unknown"
	end

	return client_ip
end

--Get the client user agent
function get_user_agent()
	local user_agent = ngx.var.http_user_agent
	if user_agent == nil then
		user_agent = "unknown"
	end
	return user_agent
end

-- 内部使用的异步写文件函数
local function async_log_write(premature, log_name, log_line)
	-- 如果 Nginx 正在退出，则不执行
	if premature then
		return
	end

	local io = require("io")
	local file = io.open(log_name, "a")
	if file then
		file:write(log_line .. "\n")
		file:close()
	end
end

--WAF log record for json,(use logstash codec => json)
function log_record(method, url, data, ruletag)
	local cjson = require("cjson")
	-- local io = require("io")
	local log_path = config_log_dir
	local client_ip = get_client_ip()
	local user_agent = get_user_agent()
	local server_name = ngx.var.server_name
	local local_time = ngx.localtime()
	local log_json_obj = {
		client_ip = client_ip,
		local_time = local_time,
		server_name = server_name,
		user_agent = user_agent,
		attack_method = method,
		req_url = url,
		req_data = data,
		rule_tag = ruletag,
	}
	local log_line = cjson.encode(log_json_obj)
	local log_name = log_path .. "/" .. ngx.today() .. "_waf.log"

	-- 使用 ngx.timer.at 开启异步任务
	-- 0 表示立即在后台执行
	local ok, err = ngx.timer.at(0, async_log_write, log_name, log_line)
	if not ok then
		ngx.log(ngx.ERR, "failed to create timer for logging: ", err)
	end
end

--WAF return
function waf_output()
	if config_waf_output == "redirect" then
		ngx.redirect(config_waf_redirect_url, 301)
	else
		ngx.header.content_type = "text/html"
		ngx.status = ngx.HTTP_FORBIDDEN
		ngx.say(config_output_html)
		ngx.exit(ngx.status)
	end
end

-- 预加载所有规则到内存缓存
local rules = {
	"whiteip.rule",
	"blackip.rule",
	"trusted_proxy.rule",
	"whiteurl.rule",
	"useragent.rule",
	"cookie.rule",
	"url.rule",
	"args.rule",
	"post.rule",
	"black_country.rule",
	"white_country.rule",
}
for _, name in ipairs(rules) do
	get_rule(name)
end
