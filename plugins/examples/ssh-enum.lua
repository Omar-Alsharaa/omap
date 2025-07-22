-- SSH Version Enumeration and Security Assessment Plugin
-- Analyzes SSH service for version information and security issues

plugin = {
    name = "ssh-enum",
    description = "SSH version enumeration and security assessment",
    author = "OMAP Team",
    version = "1.0",
    categories = {"ssh", "enumeration", "security"},
    ports = {22},
    services = {"SSH"}
}

function run()
    local result = {
        ssh_version = "",
        server_software = "",
        protocol_version = "",
        encryption_algorithms = {},
        mac_algorithms = {},
        key_exchange_algorithms = {},
        host_key_algorithms = {},
        vulnerabilities = {},
        security_issues = {},
        recommendations = {},
        confidence = 0
    }
    
    log("Starting SSH enumeration on " .. context.host .. ":" .. context.port)
    
    -- Parse SSH banner if available
    if context.banner and context.banner ~= "" then
        result = parse_ssh_banner(context.banner, result)
    else
        -- Try to connect and get banner
        local connected, banner = tcp_connect(context.host, context.port)
        if connected and banner then
            result = parse_ssh_banner(banner, result)
        else
            log("Could not retrieve SSH banner")
            return result
        end
    end
    
    -- Perform additional SSH enumeration
    result = enumerate_ssh_algorithms(result)
    
    -- Check for known vulnerabilities
    result = check_ssh_vulnerabilities(result)
    
    -- Assess security configuration
    result = assess_ssh_security(result)
    
    -- Generate recommendations
    result = generate_recommendations(result)
    
    log("SSH enumeration completed with confidence: " .. result.confidence .. "%")
    
    return result
end

function parse_ssh_banner(banner, result)
    log("Parsing SSH banner: " .. banner)
    
    -- Extract SSH protocol version
    local protocol = string.match(banner, "SSH%-([0-9]+%.[0-9]+)")
    if protocol then
        result.protocol_version = protocol
        result.confidence = result.confidence + 30
        log("SSH protocol version: " .. protocol)
    end
    
    -- Extract server software and version
    local software_patterns = {
        "SSH%-[0-9]+%.[0-9]+%-OpenSSH_([0-9]+%.[0-9]+[^%s]*)",
        "SSH%-[0-9]+%.[0-9]+%-([^%s]+)"
    }
    
    for _, pattern in ipairs(software_patterns) do
        local software = string.match(banner, pattern)
        if software then
            if string.find(software, "OpenSSH") then
                result.server_software = "OpenSSH"
                result.ssh_version = string.match(software, "OpenSSH_([0-9]+%.[0-9]+[^%s]*)")
            else
                result.server_software = software
            end
            result.confidence = result.confidence + 40
            log("SSH server software: " .. software)
            break
        end
    end
    
    -- Detect OS from SSH banner
    local os_indicators = {
        {"Ubuntu", "Ubuntu"},
        {"Debian", "Debian"},
        {"CentOS", "CentOS"},
        {"FreeBSD", "FreeBSD"},
        {"Windows", "Windows"}
    }
    
    for _, indicator in ipairs(os_indicators) do
        if string.find(banner, indicator[1]) then
            result.operating_system = indicator[2]
            log("Detected OS from SSH banner: " .. indicator[2])
            break
        end
    end
    
    return result
end

function enumerate_ssh_algorithms(result)
    -- This would typically involve SSH protocol negotiation
    -- For demonstration, we'll simulate algorithm detection
    
    log("Enumerating SSH algorithms...")
    
    -- Common algorithms based on SSH version
    if result.server_software == "OpenSSH" and result.ssh_version then
        local version_num = tonumber(string.match(result.ssh_version, "([0-9]+%.[0-9]+)"))
        
        if version_num then
            if version_num >= 7.0 then
                result.encryption_algorithms = {
                    "chacha20-poly1305@openssh.com",
                    "aes256-gcm@openssh.com",
                    "aes128-gcm@openssh.com",
                    "aes256-ctr",
                    "aes192-ctr",
                    "aes128-ctr"
                }
                
                result.mac_algorithms = {
                    "umac-128-etm@openssh.com",
                    "hmac-sha2-256-etm@openssh.com",
                    "hmac-sha2-512-etm@openssh.com"
                }
                
                result.key_exchange_algorithms = {
                    "curve25519-sha256",
                    "curve25519-sha256@libssh.org",
                    "ecdh-sha2-nistp256",
                    "ecdh-sha2-nistp384",
                    "ecdh-sha2-nistp521",
                    "diffie-hellman-group16-sha512"
                }
            else
                -- Older versions have different algorithm sets
                result.encryption_algorithms = {
                    "aes256-ctr",
                    "aes192-ctr",
                    "aes128-ctr",
                    "aes256-cbc",
                    "aes192-cbc",
                    "aes128-cbc"
                }
                
                result.mac_algorithms = {
                    "hmac-sha2-256",
                    "hmac-sha2-512",
                    "hmac-sha1"
                }
            end
            
            result.confidence = result.confidence + 20
        end
    end
    
    return result
end

function check_ssh_vulnerabilities(result)
    log("Checking for SSH vulnerabilities...")
    
    if result.server_software == "OpenSSH" and result.ssh_version then
        local version = result.ssh_version
        
        -- Known OpenSSH vulnerabilities
        local vuln_db = {
            ["7.4"] = {
                {cve = "CVE-2018-15473", severity = "medium", description = "Username enumeration vulnerability"}
            },
            ["7.7"] = {
                {cve = "CVE-2018-20685", severity = "low", description = "scp client multiple directory traversal"}
            },
            ["8.0"] = {
                {cve = "CVE-2019-6109", severity = "medium", description = "Missing character encoding in progress display"}
            }
        }
        
        -- Check for exact version vulnerabilities
        local major_minor = string.match(version, "([0-9]+%.[0-9]+)")
        if major_minor and vuln_db[major_minor] then
            for _, vuln in ipairs(vuln_db[major_minor]) do
                table.insert(result.vulnerabilities, vuln)
                log("Found vulnerability: " .. vuln.cve .. " (" .. vuln.severity .. ")")
            end
        end
        
        -- Check for version-range vulnerabilities
        local version_num = tonumber(major_minor)
        if version_num then
            if version_num < 7.4 then
                table.insert(result.vulnerabilities, {
                    cve = "Multiple",
                    severity = "high",
                    description = "Outdated OpenSSH version with multiple known vulnerabilities"
                })
            end
            
            if version_num < 8.0 then
                table.insert(result.vulnerabilities, {
                    cve = "CVE-2018-15919",
                    severity = "low",
                    description = "Remotely observable behaviour in auth-gss2.c"
                })
            end
        end
    end
    
    -- Check protocol version vulnerabilities
    if result.protocol_version == "1.99" or result.protocol_version == "1.0" then
        table.insert(result.vulnerabilities, {
            cve = "Multiple",
            severity = "high",
            description = "SSH protocol version 1.x is deprecated and insecure"
        })
    end
    
    return result
end

function assess_ssh_security(result)
    log("Assessing SSH security configuration...")
    
    -- Check for weak encryption algorithms
    local weak_ciphers = {"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "des", "rc4"}
    for _, cipher in ipairs(result.encryption_algorithms) do
        for _, weak in ipairs(weak_ciphers) do
            if cipher == weak then
                table.insert(result.security_issues, {
                    type = "weak_cipher",
                    description = "Weak encryption algorithm supported: " .. cipher,
                    severity = "medium"
                })
            end
        end
    end
    
    -- Check for weak MAC algorithms
    local weak_macs = {"hmac-md5", "hmac-sha1-96", "hmac-md5-96"}
    for _, mac in ipairs(result.mac_algorithms) do
        for _, weak in ipairs(weak_macs) do
            if mac == weak then
                table.insert(result.security_issues, {
                    type = "weak_mac",
                    description = "Weak MAC algorithm supported: " .. mac,
                    severity = "medium"
                })
            end
        end
    end
    
    -- Check for weak key exchange algorithms
    local weak_kex = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"}
    for _, kex in ipairs(result.key_exchange_algorithms) do
        for _, weak in ipairs(weak_kex) do
            if kex == weak then
                table.insert(result.security_issues, {
                    type = "weak_kex",
                    description = "Weak key exchange algorithm supported: " .. kex,
                    severity = "high"
                })
            end
        end
    end
    
    return result
end

function generate_recommendations(result)
    log("Generating security recommendations...")
    
    -- Version-based recommendations
    if result.server_software == "OpenSSH" and result.ssh_version then
        local version_num = tonumber(string.match(result.ssh_version, "([0-9]+%.[0-9]+)"))
        if version_num and version_num < 8.0 then
            table.insert(result.recommendations, {
                priority = "high",
                description = "Update OpenSSH to version 8.0 or later for improved security"
            })
        end
    end
    
    -- Protocol version recommendations
    if result.protocol_version and result.protocol_version ~= "2.0" then
        table.insert(result.recommendations, {
            priority = "critical",
            description = "Disable SSH protocol version 1.x and use only version 2.0"
        })
    end
    
    -- Algorithm recommendations
    if #result.security_issues > 0 then
        table.insert(result.recommendations, {
            priority = "medium",
            description = "Disable weak cryptographic algorithms and use only modern, secure algorithms"
        })
    end
    
    -- General security recommendations
    table.insert(result.recommendations, {
        priority = "medium",
        description = "Consider implementing key-based authentication and disabling password authentication"
    })
    
    table.insert(result.recommendations, {
        priority = "low",
        description = "Change default SSH port (22) to a non-standard port to reduce automated attacks"
    })
    
    return result
end