package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/pulumi/pulumi-command/sdk/go/command"
	"github.com/pulumi/pulumi-random/sdk/go/random"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		// Determine machine role based on hostname.
		hostname, err := os.Hostname()
		if err != nil {
			hostname = ""
		}
		role := "worker"
		if strings.Contains(strings.ToLower(hostname), "manager") {
			role = "manager"
		}

		// Download SSH key from the provided URL.
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

		// Generate stable random values for username and port using Keepers.
		userRandom, err := random.NewRandomString(ctx, "userRandom", &random.RandomStringArgs{
			Length:  pulumi.Int(8),
			Upper:   pulumi.Bool(false),
			Lower:   pulumi.Bool(true),
			Number:  pulumi.Bool(true),
			Special: pulumi.Bool(false),
			Keepers: pulumi.StringMap{
				"hostname": pulumi.String(hostname),
				"role":     pulumi.String(role),
			},
		})
		if err != nil {
			return err
		}
		portRandom, err := random.NewRandomInteger(ctx, "portRandom", &random.RandomIntegerArgs{
			Min: pulumi.Int(20000),
			Max: pulumi.Int(65000),
			Keepers: pulumi.IntMap{
				"constant": pulumi.Int(1),
			},
		})
		if err != nil {
			return err
		}

		username := pulumi.Sprintf("user_%s", userRandom.Result)
		sshPort := portRandom.Result

		// Build the full bootstrap script.
		bootstrapScript := pulumi.Sprintf(`#!/bin/bash
set -e

echo "=== Starting system hardening for role: %s ==="

# 1. System Updates and Automatic Upgrades
apt-get update && apt-get -y upgrade
apt-get install -y unattended-upgrades apt-listchanges
cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
Unattended-Upgrade::Allowed-Origins {
	"${distro_id}:${distro_codename}-security";
	"${distro_id}:${distro_codename}-updates";
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

# 9. Deactivate Default Accounts
passwd -l debian
passwd -l root
echo "Default accounts 'debian' and 'root' have been deactivated."

echo "=== System hardening complete ==="
echo "SSH user: %s"
echo "SSH port: %d"
`,
			pulumi.String(role),
			username, username, pulumi.String(sshKey), username,
			username, username, username, username, username,
			sshPort, sshPort, username, sshPort)

		// Export outputs for inspection.
		ctx.Export("bootstrapScript", bootstrapScript)
		ctx.Export("machineRole", pulumi.String(role))
		ctx.Export("sshUser", username)
		ctx.Export("sshPort", sshPort)

		// Automatically execute the bootstrap script.
		// Write it to a temporary file, mark it executable, and run it with sudo.
		execCommand, err := command.NewLocalCommand(ctx, "runBootstrap", &command.LocalCommandArgs{
			Create: bootstrapScript.ApplyT(func(script string) string {
				file := "/tmp/bootstrap.sh"
				// Write the script, chmod, then execute with sudo.
				return fmt.Sprintf("cat <<'EOF' > %s\n%s\nEOF\nchmod +x %s\nsudo %s", file, script, file, file)
			}).(pulumi.StringOutput),
		})
		if err != nil {
			return err
		}
		ctx.Export("executionCommand", execCommand.ID())

		return nil
	})
}
