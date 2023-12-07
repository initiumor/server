# Server Initialization

Tested on Debian 12.

## Installation

Before running this script, make sure you copy your public key to the server, otherwise you may run the command below.

```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub root@server-ip
```

Set up a basic server.

```bash
curl -sSfL https://testingcf.jsdelivr.net/gh/initiumor/server@main/setup.sh | bash -s - basic
```

## Notes

[AppArmor.d](https://apparmor.pujol.io/) built at [e979fe0](https://github.com/roddhjav/apparmor.d/tree/e979fe05b06f525e5a65c767b4eabe5600147355)
