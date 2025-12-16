--waf core lib
require("config")

local _rule_cache = {}

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
	local client_ip = "unknown"
	local X_FORWARDED_FOR = ngx.var.http_x_forwarded_for

	if X_FORWARDED_FOR then
		local first_ip = string.match(X_FORWARDED_FOR, "^%s*([^%s,]+)")
		if first_ip then
			client_ip = first_ip
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

--Get WAF rule
--[[ function get_rule(rulefilename)
	local io = require("io")
	local rule_path = config_rule_dir
	local rule_file = io.open(rule_path .. "/" .. rulefilename, "r")
	if rule_file == nil then
		return
	end
	local rule_table = {}
	for line in rule_file:lines() do
		line = string.gsub(line, "[\r\n%s]+", "")
		if line ~= "" then
			table.insert(rule_table, line)
		end
	end
	rule_file:close()
	return rule_table
end ]]

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
	--[[ local file = io.open(log_name, "a")
	if file == nil then
		return
	end
	file:write(log_line .. "\n")
	--file:flush()
	file:close() ]]

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
	"whiteurl.rule",
	"useragent.rule",
	"cookie.rule",
	"url.rule",
	"args.rule",
	--"post.rule",
}
for _, name in ipairs(rules) do
	get_rule(name)
end
