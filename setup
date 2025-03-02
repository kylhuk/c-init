package main

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		// Determine the machine's role based on its hostname.
		hostname, err := os.Hostname()
		if err != nil {
			hostname = ""
		}
		var role string
		if strings.Contains(strings.ToLower(hostname), "manager") {
			role = "manager"
		} else {
			role = "worker"
		}

		// Download the SSH public key from GitHub.
		sshKeyURL := "https://raw.githubusercontent.com/kylhuk/c-init/refs/heads/main/assets/key1"
		resp, err := http.Get(sshKeyURL)
		if err != nil {
			return fmt.Errorf("failed to download SSH key: %w", err)
		}
		defer resp.Body.Close()
		sshKeyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read SSH key: %w", err)
		}
		sshKey := string(sshKeyBytes)

		// Generate a random SSH username.
		rand.Seed(time.Now().UnixNano())
		username := fmt.Sprintf("user_%08x", rand.Uint32())

		// Generate a random SSH port (range: 20000 - 65000).
		sshPort := 20000 + rand.Intn(45000)

		// Construct a comprehensive bootstrap script that applies best-practice hardening.
		bootstrapScript := fmt.Sprintf(`#!/bin/bash
set -e

echo "=== Starting system hardening for role: %s ==="

# 1. System Updates and Automatic Upgrades
apt-get update && apt-get -y upgrade
apt-get install -y unattended-upgrades apt-listchanges
cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
Unattended-Upgrade::Allowed-Origins {
	"\${distro_id}:\${distro_codename}-security";
	"\${distro_id}:\${distro_codename}-updates";
};
Unattended-Upgrade::Automatic-Reboot "true";
EOF
dpkg-reconfigure -f noninteractive unattended-upgrades

# 2. Install Security and Monitoring Tools
apt-get install -y ufw fail2ban auditd rkhunter lynis aide apparmor
systemctl enable auditd && systemctl start auditd

# 3. Intrusion Detection and Integrity Monitoring
if [ ! -f /var/lib/aide/aide.db ]; then
    aideinit && cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
fi
rkhunter --update && rkhunter --propupd
lynis audit system --quiet

# 4. Secure SSH Configuration
sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

# 5. Kernel Parameter Hardening
cat >> /etc/sysctl.conf <<EOF
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.log_martians = 1
EOF
sysctl -p

# 6. Firewall Configuration with UFW
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'Temporary SSH access for bootstrap'
ufw --force enable

# 7. Create a Non-Root User for SSH Access
useradd -m -s /bin/bash %s
mkdir -p /home/%s/.ssh
echo "%s" > /home/%s/.ssh/authorized_keys
chown -R %s:%s /home/%s/.ssh
chmod 700 /home/%s/.ssh
chmod 600 /home/%s/.ssh/authorized_keys

# 8. Finalize SSH Configuration: Randomize SSH Port
echo "Waiting for security services to initialize..."
sleep 10
sed -i 's/^#Port 22/Port %d/' /etc/ssh/sshd_config
systemctl restart sshd
ufw delete allow 22/tcp
ufw allow %d/tcp comment 'SSH access after hardening'

echo "=== System hardening complete ==="
echo "SSH user: %s"
echo "SSH port: %d"
`, role, username, username, sshKey, username, username, username, username, username, username, sshPort, sshPort, username, sshPort)

		// Export outputs for reference.
		ctx.Export("sshUser", pulumi.String(username))
		ctx.Export("sshPort", pulumi.Int(sshPort))
		ctx.Export("machineRole", pulumi.String(role))
		ctx.Export("bootstrapScript", pulumi.String(bootstrapScript))

		return nil
	})
}
