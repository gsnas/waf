--WAF config file,enable = "on", disable = "off"

--waf status
config_waf_enable = "on"
--log dir
config_log_dir = "/tmp"
--rule setting
config_rule_dir = "/etc/nginx/waf/rule-config"
--enable/disable white url
config_white_url_check = "on"
--enable/disable white ip
config_white_ip_check = "on"
--enable/disable block ip
config_black_ip_check = "on"
-- enable/disable white country (only effective if black country is off)
config_white_country_check = "off"
-- enable/disable black country (takes priority over white)
config_black_country_check = "on"
--enable/disable url filtering
config_url_check = "on"
--enalbe/disable url args filtering
config_url_args_check = "on"
--enable/disable user agent filtering
config_user_agent_check = "on"
--enable/disable cookie deny filtering
config_cookie_check = "on"
--enable/disable cc filtering
config_cc_check = "on"
-- CC Protection (Leaky Bucket Algorithm):
-- Average rate: format "requests/time_in_seconds", defines the long-term average allowed request frequency
-- Example: "30/60" → average 0.5 requests per second (approximately 30 requests in 60 seconds)
config_cc_rate = "30/60"
-- Burst tolerance: maximum number of requests allowed in a short burst
-- Exceeding this will trigger immediate rate limiting or blocking
-- Example: 20 → allows up to 20 requests in a sudden burst
config_cc_burst = 20
--enable/disable post filtering
config_post_check = "off"
--config waf output redirect/html
config_waf_output = "html"
--if config_waf_output ,setting url
config_waf_redirect_url = "https://waf.xxx.net"
--[[ config_output_html = [[
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Content-Language" content="zh-cn" />
<title>403</title>
</head>
<body>
<h1 align="center"> 403
</body>
</html>
]]
config_output_html = [[
    <!DOCTYPE html>
    <html style="height:100%">
    <head>
        <meta charset="utf-8" />
        <title>403 Forbidden</title>
    </head>
    <body style="margin:0; height:100%; overflow:hidden;">
        <iframe src="https://waf.xxx.net/403.html" 
                style="width:100%; height:100%; border:none;" 
                frameborder="0">
        </iframe>
    </body>
    </html>
]]
