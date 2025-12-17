require("init")

function waf_main()
	-- 1. IP 白名单：命中则直接结束整个请求的处理，放行
	if white_ip_check() then
		return
	end

	-- 2. IP 黑名单：命中则直接结束整个请求的处理，拒绝
	if black_ip_check() then
		return
	end

	-- 3. URL 白名单：命中则直接结束处理（跳过 CC 和攻击检查）
	if white_url_check() then
		return
	end

	-- 4. UA 检查
	if user_agent_attack_check() then
		return
	end

	-- 5. CC 检查
	if cc_attack_check() then
		return
	end

	-- 6. Cookie 检查
	if cookie_attack_check() then
		return
	end

	-- 7. URL 检查
	if url_attack_check() then
		return
	end

	-- 8. ARG 检查
	if url_args_attack_check() then
		return
	end

	-- 9. POST 检查
	if post_attack_check() then
		return
	end
end

waf_main()
