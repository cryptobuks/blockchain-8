Sample init scripts and service configuration for crowcoind
==========================================================

Sample scripts and configuration files for systemd, Upstart and OpenRC
can be found in the contrib/init folder.

    contrib/init/crowcoind.service:    systemd service unit configuration
    contrib/init/crowcoind.openrc:     OpenRC compatible SysV style init script
    contrib/init/crowcoind.openrcconf: OpenRC conf.d file
    contrib/init/crowcoind.conf:       Upstart service configuration file
    contrib/init/crowcoind.init:       CentOS compatible SysV style init script

1. Service User
---------------------------------

All three Linux startup configurations assume the existence of a "crowcoin" user
and group.  They must be created before attempting to use these scripts.
The OS X configuration assumes crowcoind will be set up for the current user.

2. Configuration
---------------------------------

At a bare minimum, crowcoind requires that the rpcpassword setting be set
when running as a daemon.  If the configuration file does not exist or this
setting is not set, crowcoind will shutdown promptly after startup.

This password does not have to be remembered or typed as it is mostly used
as a fixed token that crowcoind and client programs read from the configuration
file, however it is recommended that a strong and secure password be used
as this password is security critical to securing the wallet should the
wallet be enabled.

If crowcoind is run with the "-server" flag (set by default), and no rpcpassword is set,
it will use a special cookie file for authentication. The cookie is generated with random
content when the daemon starts, and deleted when it exits. Read access to this file
controls who can access it through RPC.

By default the cookie is stored in the data directory, but it's location can be overridden
with the option '-rpccookiefile'.

This allows for running crowcoind without having to do any manual configuration.

`conf`, `pid`, and `wallet` accept relative paths which are interpreted as
relative to the data directory. `wallet` *only* supports relative paths.

For an example configuration file that describes the configuration settings,
see `contrib/debian/examples/crowcoin.conf`.

3. Paths
---------------------------------

3a) Linux

All three configurations assume several paths that might need to be adjusted.

Binary:              `/usr/bin/crowcoind`  
Configuration file:  `/etc/crowcoin/crowcoin.conf`  
Data directory:      `/var/lib/crowcoind`  
PID file:            `/var/run/crowcoind/crowcoind.pid` (OpenRC and Upstart) or `/var/lib/crowcoind/crowcoind.pid` (systemd)  
Lock file:           `/var/lock/subsys/crowcoind` (CentOS)  

The configuration file, PID directory (if applicable) and data directory
should all be owned by the crowcoin user and group.  It is advised for security
reasons to make the configuration file and data directory only readable by the
crowcoin user and group.  Access to crowcoin-cli and other crowcoind rpc clients
can then be controlled by group membership.

3b) Mac OS X

Binary:              `/usr/local/bin/crowcoind`  
Configuration file:  `~/Library/Application Support/Crowcoin/crowcoin.conf`  
Data directory:      `~/Library/Application Support/Crowcoin`
Lock file:           `~/Library/Application Support/Crowcoin/.lock`

4. Installing Service Configuration
-----------------------------------

4a) systemd

Installing this .service file consists of just copying it to
/usr/lib/systemd/system directory, followed by the command
`systemctl daemon-reload` in order to update running systemd configuration.

To test, run `systemctl start crowcoind` and to enable for system startup run
`systemctl enable crowcoind`

4b) OpenRC

Rename crowcoind.openrc to crowcoind and drop it in /etc/init.d.  Double
check ownership and permissions and make it executable.  Test it with
`/etc/init.d/crowcoind start` and configure it to run on startup with
`rc-update add crowcoind`

4c) Upstart (for Debian/Ubuntu based distributions)

Drop crowcoind.conf in /etc/init.  Test by running `service crowcoind start`
it will automatically start on reboot.

NOTE: This script is incompatible with CentOS 5 and Amazon Linux 2014 as they
use old versions of Upstart and do not supply the start-stop-daemon utility.

4d) CentOS

Copy crowcoind.init to /etc/init.d/crowcoind. Test by running `service crowcoind start`.

Using this script, you can adjust the path and flags to the crowcoind program by
setting the CROWCOIND and FLAGS environment variables in the file
/etc/sysconfig/crowcoind. You can also use the DAEMONOPTS environment variable here.

4e) Mac OS X

Copy org.crowcoin.crowcoind.plist into ~/Library/LaunchAgents. Load the launch agent by
running `launchctl load ~/Library/LaunchAgents/org.crowcoin.crowcoind.plist`.

This Launch Agent will cause crowcoind to start whenever the user logs in.

NOTE: This approach is intended for those wanting to run crowcoind as the current user.
You will need to modify org.crowcoin.crowcoind.plist if you intend to use it as a
Launch Daemon with a dedicated crowcoin user.

5. Auto-respawn
-----------------------------------

Auto respawning is currently only configured for Upstart and systemd.
Reasonable defaults have been chosen but YMMV.
