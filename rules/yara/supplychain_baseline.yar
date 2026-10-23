/*
  YARA Rules for Baseline Supply Chain Scanning (Track 2)
  Detects common malicious payload patterns in package installation scripts (setup.py, package.json).
  Note: Plain signatures are blind to advanced AST obfuscation (chr-arrays, string concat, base64 eval).
*/

rule PyPI_Obvious_Reverse_Shell {
    meta:
        description = "Detects plain socket reverse shell in Python code"
        date = "2026-10-16"
        reference = "MITRE ATT&CK T1059.006"
    strings:
        $s1 = "socket.socket" ascii
        $s2 = "subprocess.call" ascii
        $s3 = "/bin/sh" ascii
        $s4 = "os.dup2" ascii
    condition:
        all of them
}

rule PyPI_Plain_C2_Exfiltration {
    meta:
        description = "Detects plain HTTP request transmitting sensitive files (/etc/passwd, token)"
        date = "2026-10-16"
    strings:
        $url1 = "http://" ascii
        $url2 = "https://" ascii
        $req1 = "urllib.request.urlopen" ascii
        $req2 = "requests.post" ascii
        $sens1 = "/etc/passwd" ascii
        $sens2 = "os.environ" ascii
    condition:
        ($url1 or $url2) and ($req1 or $req2) and ($sens1 or $sens2)
}

rule PyPI_Generic_Base64_Exec {
    meta:
        description = "Detects plain base64 b64decode wrapped directly in exec"
        date = "2026-10-16"
    strings:
        $b1 = "exec(base64.b64decode" ascii
        $b2 = "eval(base64.b64decode" ascii
    condition:
        $b1 or $b2
}

rule NPM_Suspicious_Postinstall {
    meta:
        description = "Detects suspicious curl/wget execution in package.json scripts"
        date = "2026-10-16"
    strings:
        $p1 = "\"postinstall\"" ascii
        $p2 = "\"preinstall\"" ascii
        $c1 = "curl" ascii
        $c2 = "wget" ascii
        $c3 = "bash -i" ascii
    condition:
        ($p1 or $p2) and ($c1 or $c2 or $c3)
}
