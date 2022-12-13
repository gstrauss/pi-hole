-- pihole.lua - lighttpd mod_magnet lua script
--   minimally-invasive overlay on top of existing lighttpd request processing
--   permit HTTP requests to vhost whitelist
--   permit and handle pihole admin hosts /admin/ pages
--   reject HTTP requests to hosts not on vhost whitelist or pihole admin hosts
--
-- Pi-hole: A black hole for Internet advertisements
-- (c) 2022 Pi-hole, LLC (https://pi-hole.net)
-- Network-wide ad blocking via your own hardware.
--
-- This file is copyright under the latest version of the EUPL.
-- Please see LICENSE file for your rights under this license.

-- To use: install this script as /etc/lighttpd/pihole.lua
--
-- Add /etc/lighttpd/conf.d/pihole.conf containing:
--
--   server.modules += ("mod_magnet")
--   magnet.attract-physical-path-to += ("/etc/lighttpd/pihole.lua")
--
-- #(Fedora: /etc/lighttpd/conf.d/pihole.conf)
-- #(Debian: /etc/lighttpd/conf-available/15-pihole.conf)
-- #(Debian: named 15-pihole.conf to sort after Debian 05-auth.conf)
-- #(Debian: use lighty-enable-mod to symlink into conf-enabled)
--
-- Add /etc/lighttpd/conf.d/pihole-admin.conf containing:
--
--   server.modules += ("mod_fastcgi")
--   $HTTP["url"] =~ "^/admin/" {
--      server.stream-response-body = 1
--      fastcgi.server = (
--          ".php" => (
--              "localhost" => (
--                  "socket" => "/tmp/pihole-php-fastcgi.socket",
--                  "bin-path" => "/usr/bin/php-cgi",
--                  "min-procs" => 0,  # 0 allowed in lighttpd 1.4.46+
--                  "max-procs" => 1,
--              )
--          )
--      )
--   }
--
--   # custom access/error logging
--   # (use lighttpd default access and error logs if commented out)
--   # (logging not enabled here because it does not appear that
--   #  pi-hole sets up log rotation of pihole custom error logs)
--   #
--   # /var/log/lighttpd/error-pihole.log referenced by
--   #   AdminLTE/scripts/pi-hole/php/auth.php
--   #   AdminLTE/scripts/pi-hole/js/db_queries.js
--   #
--   #server.error-log   := "/var/log/lighttpd/error-pihole.log"
--   #
--   # /var/log/lighttpd/access-pihole.log not referenced by pi-hole scripts
--   #
--   #accesslog.filename := "/var/log/lighttpd/access-pihole.log"
--   #accesslog.format   := "%{%s}t|%V|%r|%s|%b"
--   #
--   # To avoid excess logging, user might configure server.error-log per local
--   # vhost, and set server.error-log = "/dev/null" in global scope.  If that
--   # is done, then note that the error log in global scope may need to be
--   # temporarily re-enabled if the need to troubleshoot arises, since some
--   # types of errors occur prior to the vhost being known, and so prior to
--   # lighttpd being able to identify and use the per-local-vhost error-log.
--
-- #(Fedora: /etc/lighttpd/conf.d/pihole-admin.conf)
-- #(Debian: /etc/lighttpd/conf-available/15-pihole-admin.conf)
-- #(Debian: use lighty-enable-mod to symlink into conf-enabled)
-- Those using lighttpd with existing configurations may wish to modify settings
-- in 15-pihole-admin.conf to scope it only to
--   pihole admin hosts (e.g. "pi.hole", "localhost")
-- or to a specific socket (e.g. $SERVER["socket"] == "127.0.0.1:8080")
-- since 15-pihole-admin.conf as written above adds pihole "/admin/" namespace
-- into every vhost on the server.  (Implementer's note: the pihole admin pages
-- would be better isolated if reachable in a more uniquely-named namespace,
-- e.g. "/pihole/".  In the future, we might rewrite URLs to "/pihole/admin/"
-- namespace here when the host is determined to be a pi-hole admin host,
-- allowing fastcgi.server config above to be $HTTP["url"] =~ "^/pihole/admin/")
--
-- Historically, lighttpd.conf server.error-handler-404 = "/pihole/index.php"
-- is changed to "/pihole/custom.php" if that exists at pihole install time.
-- /pihole/index.php attempts to detect local vhost or pihole admin host and
-- serves a built-in splash/landing page for pihole admin host if the urlpath
-- "/landing.php" does not exist, and will use "/landing.php" if it exists.
-- WTH?  What a mess (poor encapsulation).  This matters only when the host is
-- a pihole admin host, and not if host is a local vhost (which should be
-- skipped) or is an adhost (which should receive a 404).
-- Supporting /pihole/custom.php or /landing.php intercept HTTP status 403,404
-- in lighttpd with server.error-handler-404 = "/pihole/index.php" could still
-- be used if that behavior is desired, but is not part of the code below.
-- The code below attempts to be a friendlier overlay onto existing lighttpd
-- local vhosts, such as localhost or 127.0.0.1 or ::1, handling only requests
-- under "/admin" prefix and only on pihole admin hosts.
--
-- As an standalone recommendation:
-- * For better encapsulation: transition /admin/ to /pihole/admin/ by setting
--   up redirect url.redirect += ("^/admin(.*)" => "/pihole/admin$1") in
--   lighttpd.conf.  Phase that out in a year or two or three.  Update doc, this
--   script, and AdminLTE to use urlpath "/pihole/admin/".  Install admin
--   scripts in /var/www/html/pihole/admin/... and symlink from old location
--   (/var/www/html/admin).

local pihole_config = "/etc/lighttpd/pihole_config.lua"

-- There are three categories of hosts
-- * user-specific local vhosts
-- * pi-hole admin hosts
-- * pi-hole blacklist hosts (everything else)

-- list of hostnames to be accepted as pi-hole admin names
local pihosts = _G.pihosts
-- list of local vhosts (i.e. not pi-hole admin host or blacklist hosts)
local vhosts = _G.vhosts
-- flag if pihosts or vhosts contain IP literals (optimization for HTTP/1.0)
local match_ip = false
-- alias physical path to (potentially) alternate outside host document root
local piroot = _G.piroot

-- initialize config once, when script is loaded (optimization)
-- pihole_config may optionally exist and may optionally define one or both:
--   pihosts = { ... }
--   vhosts = { ... }
--   piroot = "..."
-- When config file is changed, trigger lighttpd script reload with one of
--   'touch pi-hole.lua' (mod_magnet reloads script if mtime changes),
--   or restart lighttpd (e.g. send lighttpd process SIGUSR1)
if pihosts == nil then
  -- compat with mod_magnet before lighttpd 1.4.60
  --local stat = lighty.c.stat
  local stat = lighty.stat

  -- load and execute config file to define pihosts and/or vhosts lists
  -- (config is separate file to avoid need for user to modify this script)
  if stat(pihole_config) then
    dofile(pihole_config)
  end
  --
  -- potential alternative: use mcdb constant database of pihosts and vhosts
  --   (see https://wiki.lighttpd.net/AbsoLUAtion#Fight-DDoS example)

  -- set defaults if none set in config file (or if config file does not exist)
  if pihosts == nil then
    pihosts = { "pi.hole", "localhost", "127.0.0.1", "::1" }
    _G.pihosts = pihosts
  end
  if vhosts == nil then
    vhosts = {}
    _G.vhosts = vhosts
  end
  -- future: consider alternate install location instead of /var/www/html/admin/
  if piroot == nil then
    piroot = "/var/www/html"
    _G.piroot = piroot
  end

  -- set flag if either list contains IP literals (optimization for HTTP/1.0)
  local function contains_ips(list)
    for _, vhost in ipairs(list) do
      -- check if string looks like an IP literal
      -- (overmatching (false positives) is ok)
      if string.match(vhost, "^%d+%.%d+%.%d+%.%d+$") or
         string.match(vhost, "^%x*:") then
        return true
      end
    end
    return false
  end
  match_ip = contains_ips(pihosts) or contains_ips(vhosts)

  -- Note if access to pi-hole admin should be restricted by client IP,
  -- such policy should be enforced in lighttpd.conf, or in pi-hole .php,
  -- or with additional code below, perhaps enabled via configuration in
  -- pihole_config.  Such restrictions are separate from the above lists
  -- which are checked using the Host in the client HTTP request headers --
  -- which can be any client-provided data, including "127.0.0.1".

  -- Note: while pihosts and vhosts could be rewritten into indexable tables
  --      to allow e.g. vhosts[host], matching was implemented as a list scan
  --      in host_in_list() to make it simpler to enhance in the future, should
  --      there be a desire to support matching syntax besides exact match,
  --      e.g. suffix matching if list entry begins with '.' (not implemented)

  -- typical system-wide mimetype.assign defines these, but it is
  -- simple enough to define what is needed for the pi-hole admin pages
  _G.content_types = {
    [".ico"]   = "image/x-icon",
    [".jpeg"]  = "image/jpeg",
    [".jpg"]   = "image/jpeg",
    [".png"]   = "image/png",
    [".svg"]   = "image/svg+xml",
    [".css"]   = "text/css; charset=utf-8",
    [".html"]  = "text/html; charset=utf-8",
    [".js"]    = "text/javascript; charset=utf-8",
    [".json"]  = "application/json; charset=utf-8",
    [".map"]   = "application/json; charset=utf-8",
    [".txt"]   = "text/plain; charset=utf-8",
    [".eot"]   = "application/vnd.ms-fontobject",
    [".otf"]   = "font/otf",
    [".ttc"]   = "font/collection",
    [".ttf"]   = "font/ttf",
    [".woff"]  = "font/woff",
    [".woff2"] = "font/woff2"
  }
end



local function pi_hole_response()
  -- (This might be enhanced for image requests to instead return single pixel
  --  image along with HTTP caching response headers (e.g. Cache-Control))
  return 404
end

local function host_in_list(host, list)
  for _, vhost in ipairs(list) do
    if (host == vhost) then
      return true
    end
  end
  return false
end



-- compat with mod_magnet before lighttpd 1.4.60
-- local r = lighty.r
-- local req_header = r.req_header
-- local req_attr = r.req_attr
local req_header = lighty.request
local req_attr = lighty.env

local host = req_header["Host"]
if host == nil then
  -- use server IP address if no Host request header provided
  -- (avoid getsockname() overhead on wildcard IP unless match_ip is set)
  -- (match_ip is set from config to flag existence of literal IPs in lists)
  host = match_ip and req_attr["request.server-addr"] or ""
end

-- do not handle user-specific local vhosts
if host_in_list(host, vhosts) then
  return 0
end

-- reject all requests to pi-hole blacklist hosts
-- (i.e. everything else besides pi-hole admin host)
if not host_in_list(host, pihosts) then
  return pi_hole_response()
end

--
-- handle pi-hole admin host
--
-- This might subsume pi-hole customizations to lighttpd.conf for use of
-- lighttpd mod_access, mod_alias, mod_indexfile, mod_setenv, mod_expire --
-- save for running this lua script.  This is an alternative;
-- handling /admin/ could remain in lighttpd.conf, though using
-- this script is better-scoped only to matching the defined pihosts.
--

-- compat with mod_magnet before lighttpd 1.4.60
--local stat = lighty.c.stat
local stat = lighty.stat
-- local resp_header = r.resp_header
local resp_header = lighty.header

local urlpath = req_attr["uri.path"]
if not string.match(urlpath, "^/admin") then
  -- Let lighttpd handle request using other modules
  return 0
elseif urlpath == "/admin" then
  -- redirect to Web Interface
  resp_header["Location"] = "/admin/"
  return 301
end

local path
if urlpath == "/admin/" then
  urlpath = "/admin/index.php"
  path = piroot .. urlpath
  local st = stat(path)
  if not st then -- request target does not exist in filesystem
    return 404   -- missing /admin/index.php; not installed in piroot?
  end
  req_attr["uri.path"] = urlpath
else
  if string.match(urlpath, "/%.%.") then
    -- reject /.. in path
    -- (sanity check; lighttpd path normalization should have already handled)
    return 403
  end
  path = piroot .. urlpath
  local st = stat(path)
  if not st then -- request target does not exist in filesystem
    -- redirect to Web Interface
    resp_header["Location"] = "/admin/"
    return 302
  end
  if string.match(path, "/%.") then
    -- reject dotfiles from being served, such as .git, .github, .gitignore
    return 403
  end
  if string.match(path, "~$") then
    return 403
  end
  local ext = string.match(urlpath, "(%.%w+)$")
  if ext then
    if ext == ".inc" or ext == ".md" or ext == ".yml" or ext == ".ini" then
      return 403
    end

    -- set Cache-Control defaults for files which are not dynamic (.php)
    if ext ~= ".php" then
      resp_header["Cache-Control"] = "max-age=300"
    end
    -- set Content-Type if known
    local content_type = _G.content_types[ext]
    if content_type then
      resp_header["Content-Type"] = content_type
    end
  else
    -- (choice: not setting Cache-Control for files without extensions)
  end
end

-- alias physical path to (potentially) alternate outside host document root
req_attr["physical.path"] = path
req_attr["physical.basedir"] = piroot

-- X-Pi-hole is a response header for debugging using curl -I
-- X-Frame-Options prevents clickjacking attacks and helps ensure your content
--   is not embedded into other sites via < frame >, < iframe > or < object >.
-- X-XSS-Protection sets the configuration for the cross-site scripting filters
--   built into most browsers. This is important because it tells the browser
--   to block the response if a malicious script has been inserted from a user
--   input. (deprecated; disabled)
-- X-Content-Type-Options stops a browser from trying to MIME-sniff the content
--   type and forces it to stick with the declared content-type. This is
--   important because the browser will only load external resources if their
--   content-type matches what is expected, and not malicious hidden code.
-- Content-Security-Policy tells the browser where resources are allowed to be
--   loaded and if it’s allowed to parse/run inline styles or Javascript. This
--   is important because it prevents content injection attacks, such as
--   Cross Site Scripting (XSS).
-- X-Permitted-Cross-Domain-Policies is an XML document that grants a web
--   client, such as Adobe Flash Player or Adobe Acrobat (though not necessarily
--   limited to these), permission to handle data across domains.
-- Referrer-Policy allows control/restriction of the amount of information
--   present in the referral header for links away from your page—the URL path
--   or even if the header is sent at all.
--
-- (some of these response headers might not be necessary for static images
--  and could instead be set by the .php files)
resp_header["X-Pi-hole"] = "The Pi-hole Web interface is working!"
resp_header["X-Frame-Options"] = "DENY"
resp_header["X-XSS-Protection"] = "0"
resp_header["X-Content-Type-Options"] = "nosniff"
resp_header["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline';"
resp_header["X-Permitted-Cross-Domain-Policies"] = "none"
resp_header["Referrer-Policy"] = "same-origin"

-- allow teleporter and API qr code iframe on settings page
-- (X-Frame-Options ought to be set by teleporter.php, api_token.php; not here)
if string.match(path, "/teleporter.php$") or
   string.match(path, "/api_token.php$") then
  resp_header["X-Frame-Options"] = "SAMEORIGIN"
end

-- Let lighttpd handle request using other modules,
-- e.g. mod_fastcgi (for .php) or mod_staticfile (for static files)
--return 0
-- (until we delete the rest of the file below)
do return 0 end



--
--
-- (below is no longer necessary;
--  was part of /pi-hole/index.php for handling 404 for pi-hole blacklist hosts)
--
--


-- pi-hole admin host built-in splash/landing page
--
-- If host name is desired in <title>, then use host_htmlenc (lighttpd 1.4.60+)
-- and pass string segments each request instead of storing in global
-- local host_htmlenc = lighty.c.xmlenc(host)

local resp_body = _G.resp_body
if resp_body == nil then
  resp_body = { [[
<!doctype html>
<html lang='en'>
    <head>
        <meta charset='utf-8'>
        <meta name='viewport' content='width=device-width, initial-scale=1'>
        <title>pi-hole</title>
        <link rel='shortcut icon' href='/admin/img/favicons/favicon.ico' type='image/x-icon'>
        <style>
            html, body { height: 100% }
            body { margin: 0; font: 13pt "Source Sans Pro", "Helvetica Neue", Helvetica, Arial, sans-serif; }
            body { background: #222; color: rgba(255, 255, 255, 0.7); text-align: center; }
            p { margin: 0; }
            a { color: #3c8dbc; text-decoration: none; }
            a:hover { color: #72afda; text-decoration: underline; }
            #splashpage { display: flex; align-items: center; justify-content: center; }
            #splashpage img { margin: 5px; width: 256px; }
            #splashpage b { color: inherit; }
        </style>
    </head>
    <body id='splashpage'>
        <div>
        <img src='/admin/img/logo.svg' alt='Pi-hole logo' width='256' height='377'>
        <br>
        <p>Pi-<strong>hole</strong>: Your black hole for Internet advertisements</p>
        <a href='/admin/'>Did you mean to go to the admin panel?</a>
        </div>
    </body>
</html>
]] }
  _G.resp_body = resp_body
end

-- compat with mod_magnet before lighttpd 1.4.60
--r.resp_body:set(resp_body)
lighty.content = resp_body

resp_header["Content-Type"] = "text/html; charset=utf-8"
return 200
