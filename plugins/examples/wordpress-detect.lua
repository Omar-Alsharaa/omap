-- WordPress Detection Plugin
-- Detects WordPress installations and attempts to identify version

plugin = {
    name = "wordpress-detect",
    description = "Detects WordPress installations and attempts version identification",
    author = "OMAP Team",
    version = "1.0",
    categories = {"web", "cms", "discovery"},
    ports = {80, 443, 8080, 8443},
    services = {"HTTP", "HTTPS"}
}

function run()
    local result = {
        wordpress_detected = false,
        version = "",
        theme = "",
        plugins = {},
        vulnerabilities = {},
        confidence = 0
    }
    
    log("Starting WordPress detection on " .. context.host .. ":" .. context.port)
    
    -- Check for common WordPress indicators
    local wp_indicators = {
        "/wp-content/",
        "/wp-admin/",
        "/wp-includes/",
        "/wp-login.php",
        "/readme.html",
        "/license.txt"
    }
    
    local detected_paths = {}
    
    for _, path in ipairs(wp_indicators) do
        local url = "http://" .. context.host .. ":" .. context.port .. path
        local response = http_get(url)
        
        if response and string.find(response, "WordPress") then
            result.wordpress_detected = true
            result.confidence = result.confidence + 20
            table.insert(detected_paths, path)
            log("WordPress indicator found: " .. path)
        end
    end
    
    if result.wordpress_detected then
        -- Try to detect version from various sources
        result.version = detect_wp_version()
        
        -- Try to detect active theme
        result.theme = detect_wp_theme()
        
        -- Try to enumerate plugins
        result.plugins = enumerate_wp_plugins()
        
        -- Check for common vulnerabilities
        result.vulnerabilities = check_wp_vulnerabilities(result.version)
        
        log("WordPress detected with confidence: " .. result.confidence .. "%")
        if result.version ~= "" then
            log("WordPress version: " .. result.version)
        end
        if result.theme ~= "" then
            log("Active theme: " .. result.theme)
        end
    else
        log("No WordPress installation detected")
    end
    
    result.detected_paths = detected_paths
    return result
end

function detect_wp_version()
    local version_sources = {
        "/readme.html",
        "/wp-includes/version.php",
        "/feed/",
        "/wp-admin/css/wp-admin.min.css"
    }
    
    for _, source in ipairs(version_sources) do
        local url = "http://" .. context.host .. ":" .. context.port .. source
        local response = http_get(url)
        
        if response then
            -- Try different version detection patterns
            local patterns = {
                "Version ([0-9]+%.[0-9]+%.[0-9]+)",
                "WordPress ([0-9]+%.[0-9]+%.[0-9]+)",
                "wp%-admin%.min%.css%?ver=([0-9]+%.[0-9]+%.[0-9]+)"
            }
            
            for _, pattern in ipairs(patterns) do
                local version = string.match(response, pattern)
                if version then
                    log("WordPress version detected from " .. source .. ": " .. version)
                    return version
                end
            end
        end
    end
    
    return ""
end

function detect_wp_theme()
    local url = "http://" .. context.host .. ":" .. context.port .. "/"
    local response = http_get(url)
    
    if response then
        -- Look for theme indicators in the HTML
        local theme_patterns = {
            "/wp%-content/themes/([^/]+)/",
            "themes/([^/]+)/style%.css"
        }
        
        for _, pattern in ipairs(theme_patterns) do
            local theme = string.match(response, pattern)
            if theme then
                log("WordPress theme detected: " .. theme)
                return theme
            end
        end
    end
    
    return ""
end

function enumerate_wp_plugins()
    local plugins = {}
    local common_plugins = {
        "akismet",
        "jetpack",
        "yoast",
        "contact-form-7",
        "wordfence",
        "elementor",
        "woocommerce"
    }
    
    for _, plugin in ipairs(common_plugins) do
        local url = "http://" .. context.host .. ":" .. context.port .. "/wp-content/plugins/" .. plugin .. "/readme.txt"
        local response = http_get(url)
        
        if response and not string.find(response, "404") then
            -- Try to extract version
            local version = string.match(response, "Stable tag: ([0-9]+%.[0-9]+%.[0-9]+)")
            if not version then
                version = string.match(response, "Version: ([0-9]+%.[0-9]+%.[0-9]+)")
            end
            
            table.insert(plugins, {
                name = plugin,
                version = version or "unknown"
            })
            
            log("WordPress plugin detected: " .. plugin .. " (" .. (version or "unknown version") .. ")")
        end
    end
    
    return plugins
end

function check_wp_vulnerabilities(version)
    local vulnerabilities = {}
    
    if version == "" then
        return vulnerabilities
    end
    
    -- Simple vulnerability database (in real implementation, this would be more comprehensive)
    local vuln_db = {
        ["5.0"] = {"CVE-2019-8942", "CVE-2019-8943"},
        ["5.1"] = {"CVE-2019-9787"},
        ["5.2"] = {"CVE-2019-16223"},
        ["4.9"] = {"CVE-2018-6389", "CVE-2017-17092"}
    }
    
    -- Check for exact version match
    if vuln_db[version] then
        for _, cve in ipairs(vuln_db[version]) do
            table.insert(vulnerabilities, {
                cve = cve,
                severity = "medium",
                description = "Known vulnerability for WordPress " .. version
            })
        end
    end
    
    -- Check for version ranges (simplified)
    local major_minor = string.match(version, "([0-9]+%.[0-9]+)")
    if major_minor then
        local major = tonumber(string.match(major_minor, "([0-9]+)"))
        local minor = tonumber(string.match(major_minor, "[0-9]+%.([0-9]+)"))
        
        -- Example: versions before 5.3 have certain vulnerabilities
        if major < 5 or (major == 5 and minor < 3) then
            table.insert(vulnerabilities, {
                cve = "CVE-2019-17671",
                severity = "high",
                description = "Outdated WordPress version with known security issues"
            })
        end
    end
    
    if #vulnerabilities > 0 then
        log("Found " .. #vulnerabilities .. " potential vulnerabilities")
    end
    
    return vulnerabilities
end