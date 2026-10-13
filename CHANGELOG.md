# Changelog

## 0.0.2

- Install the node as a service with `install`, `update` and `uninstall`, on Linux (systemd) and on Windows. The service runs as its own `nerve` user; config, keys and state are kept out of the commands' reach.
- Commands run as the account that installed the node, or as one you choose in `setup`. `setup --create-user` makes a new account with its own home folder.
- User mode, folder mode and sudo run their commands as that account. Folder mode on Linux is limited to the folders you gave.
- A node started as root, or as administrator on Windows, is refused unless `machine.allow_root` is set, and warns when it runs.
- Download and install in two steps: `sudo ./nerve-node-x86_64-linux install`.
