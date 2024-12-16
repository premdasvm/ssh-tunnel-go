# SSH Tunnel Go

A command-line tool written in Go that creates SSH tunnels for port forwarding with persistent configuration storage.

## Features

- Interactive prompts for configuration
- Support for password and private key authentication
- Configurable local and remote ports
- Graceful shutdown with Ctrl+C
- Real-time connection status
- SQLite database for storing connection configurations
- Save and reuse multiple tunnel configurations
- Named configurations for easy identification

## Prerequisites

- Go 1.16 or higher
- SSH access to the remote server

## Installation

```bash
git clone https://github.com/yourusername/ssh-tunnel-go.git
cd ssh-tunnel-go
go get github.com/mattn/go-sqlite3
go build
```

## Usage

Run the compiled binary:

```bash
./ssh-tunnel-go
```

You will be presented with two options:

1. Create new SSH tunnel
2. Use existing configuration

### Creating a New Configuration

If you choose option 1, you'll be prompted for:

1. Configuration name (for future reference)
2. Host IP address
3. SSH Port (default: 22)
4. Username
5. Authentication method (password/privatekey)
6. Password or private key file path
7. Local port to forward from
8. Remote port to forward to

The configuration will be automatically saved to the SQLite database for future use.

### Using an Existing Configuration

If you choose option 2, you'll see:

1. A list of all saved configurations
2. Select a configuration by its ID
3. The tunnel will be established using the selected configuration

## Example

To create a tunnel that forwards local port 8080 to remote port 80:

1. Run the program
2. Choose option 1 (Create new SSH tunnel)
3. Enter a name for the configuration (e.g., "local-web")
4. Enter the remote server details
5. Enter `8080` as the local port
6. Enter `80` as the remote port

Next time you need the same tunnel:

1. Run the program
2. Choose option 2 (Use existing configuration)
3. Select "local-web" from the list

The tunnel will remain active until you press Ctrl+C to stop it.

## Security Notes

- When using password authentication, the password is stored in the SQLite database
- The SQLite database file (`tunnel_configs.db`) is created in the same directory as the executable
- Consider setting appropriate file permissions for the database file
- The program uses `ssh.InsecureIgnoreHostKey()` for host key verification
