--WAF Action
require("config")
require("lib")

--args
local rulematch = ngx.re.find
local unescape = ngx.unescape_uri

-- cc_attack
local limit_req = require("resty.limit.req")
local cc_count = tonumber(string.match(config_cc_rate, "(.*)/")) or 30
local cc_seconds = tonumber(string.match(config_cc_rate, "/(.*)")) or 60
if cc_count <= 0 or cc_seconds <= 0 then
	cc_count, cc_seconds = 30, 60
end
local cc_rate = cc_count / cc_seconds
local lim, err = limit_req.new("limit", cc_rate, config_cc_burst)
if not lim then
	ngx.log(ngx.ERR, "failed to instantiate limit_req: ", err)
end

--allow white ip
function white_ip_check()
	if config_white_ip_check == "on" then
		local ip_white_rule = get_rule("whiteip.rule")
		local white_ip = get_client_ip()
		if ip_white_rule ~= nil then
			for _, rule in pairs(ip_white_rule) do
				if rule ~= "" and rulematch(white_ip, rule, "jo") then
					--log_record('white_ip',ngx.var_request_uri,"_","_")
					return true
				end
			end
		end
	end
end

--deny black ip
function black_ip_check()
	if config_black_ip_check == "on" then
		local ip_black_rule = get_rule("blackip.rule")
		local black_ip = get_client_ip()
		if ip_black_rule ~= nil then
			for _, rule in pairs(ip_black_rule) do
				if rule ~= "" and rulematch(black_ip, rule, "jo") then
					log_record("BlackList_IP", ngx.var_request_uri, "_", "_")
					if config_waf_enable == "on" then
						-- ngx.exit(403)
						waf_output()
						return true
					end
				end
			end
		end
	end
end

--allow white url
function white_url_check()
	if config_white_url_check == "on" then
		local url_white_rules = get_rule("whiteurl.rule")
		local req_uri = ngx.var.request_uri
		if url_white_rules ~= nil then
			for _, rule in pairs(url_white_rules) do
				if rule ~= "" and rulematch(req_uri, rule, "jo") then
					return true
				end
			end
		end
	end
end

--deny cc attack
function cc_attack_check()
	if config_cc_check ~= "on" or not lim then
		return false
	end

	local key = get_client_ip() .. ngx.var.uri
	local delay, err = lim:incoming(key, true)

	if not delay then
		if err == "rejected" then
			log_record("CC_Attack", ngx.var.request_uri, "-", "-")
			if config_waf_enable == "on" then
				-- ngx.exit(403)
				waf_output()
				return true
			end
		end
		ngx.log(ngx.ERR, "failed to limit req: ", err)
		return false
	end

	if delay >= 0.001 then
		ngx.sleep(delay)
	end
	return false
end

--deny cookie
function cookie_attack_check()
	if config_cookie_check == "on" then
		local cookie_rules = get_rule("cookie.rule")
		local user_cookie = ngx.var.http_cookie
		if user_cookie ~= nil then
			for _, rule in pairs(cookie_rules) do
				if rule ~= "" and rulematch(user_cookie, rule, "jo") then
					log_record("Deny_Cookie", ngx.var.request_uri, "-", rule)
					if config_waf_enable == "on" then
						waf_output()
						return true
					end
				end
			end
		end
	end
	return false
end

--deny url
function url_attack_check()
	if config_url_check == "on" then
		local url_rules = get_rule("url.rule")
		-- local req_uri = ngx.var.uri
		local req_uri = ngx.var.request_uri
		if url_rules ~= nil then
			for _, rule in pairs(url_rules) do
				if rule ~= "" and rulematch(req_uri, rule, "jo") then
					log_record("Deny_URL", req_uri, "-", rule)
					if config_waf_enable == "on" then
						waf_output()
						return true
					end
				end
			end
		end
	end
	return false
end

--deny url args
function url_args_attack_check()
	if config_url_args_check == "on" then
		local args_rules = get_rule("args.rule")
		if not args_rules then
			return false
		end
		local req_args = ngx.req.get_uri_args()
		-- 如果没有参数，直接返回，避免进入规则循环
		if not req_args or next(req_args) == nil then
			return false
		end
		for _, rule in pairs(args_rules) do
			if rule ~= "" then
				for key, val in pairs(req_args) do
					local args_data = ""
					if type(val) == "table" then
						args_data = table.concat(val, " ")
					else
						args_data = val
					end
					if
						args_data
						and type(args_data) ~= "boolean"
						and rule ~= ""
						and rulematch(unescape(args_data), rule, "jo")
					then
						log_record("Deny_URL_Args", ngx.var.request_uri, "-", rule)
						if config_waf_enable == "on" then
							waf_output()
							return true
						end
					end
				end
			end
		end
	end
	return false
end

--deny user agent
function user_agent_attack_check()
	if config_user_agent_check == "on" then
		local user_agent_rules = get_rule("useragent.rule")
		local user_agent = ngx.var.http_user_agent
		if user_agent ~= nil then
			for _, rule in pairs(user_agent_rules) do
				if rule ~= "" and rulematch(user_agent, rule, "jo") then
					log_record("Deny_USER_AGENT", ngx.var.request_uri, "-", rule)
					if config_waf_enable == "on" then
						waf_output()
						return true
					end
				end
			end
		end
	end
	return false
end

--deny post
function post_attack_check()
	if config_post_check == "on" then
		local post_rules = get_rule("post.rule")
		ngx.req.read_body()
		local post_args = ngx.req.get_post_args()

		if post_args then
			for _, rule in pairs(post_rules) do
				for key, val in pairs(post_args) do
					local post_data = type(val) == "table" and table.concat(val, " ") or val
					if post_data and type(post_data) ~= "boolean" and rule ~= "" then
						if rulematch(unescape(post_data), rule, "jo") then
							log_record("Deny_POST", ngx.var.request_uri, "-", rule)
							if config_waf_enable == "on" then
								waf_output()
								return true
							end
						end
					end
				end
			end
		end
	end
	return false
end
