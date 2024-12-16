package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/ssh"
)

type TunnelConfig struct {
	ID           int
	Name         string
	HostIP       string
	SSHPort      int
	Username     string
	AuthMethod   string
	Password     string
	PrivateKey   string
	LocalPort    int
	RemotePort   int
}

func initDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "tunnel_configs.db")
	if err != nil {
		return nil, err
	}

	createTableSQL := `
	CREATE TABLE IF NOT EXISTS tunnel_configs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		host_ip TEXT NOT NULL,
		ssh_port INTEGER NOT NULL,
		username TEXT NOT NULL,
		auth_method TEXT NOT NULL,
		password TEXT,
		private_key TEXT,
		local_port INTEGER NOT NULL,
		remote_port INTEGER NOT NULL
	);`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func saveConfig(db *sql.DB, config *TunnelConfig) error {
	stmt := `
	INSERT INTO tunnel_configs (
		name, host_ip, ssh_port, username, auth_method, 
		password, private_key, local_port, remote_port
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := db.Exec(stmt,
		config.Name, config.HostIP, config.SSHPort, config.Username,
		config.AuthMethod, config.Password, config.PrivateKey,
		config.LocalPort, config.RemotePort)
	return err
}

func listConfigs(db *sql.DB) ([]TunnelConfig, error) {
	rows, err := db.Query("SELECT id, name, host_ip, ssh_port, username, auth_method, password, private_key, local_port, remote_port FROM tunnel_configs")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var configs []TunnelConfig
	for rows.Next() {
		var config TunnelConfig
		err := rows.Scan(
			&config.ID, &config.Name, &config.HostIP, &config.SSHPort,
			&config.Username, &config.AuthMethod, &config.Password,
			&config.PrivateKey, &config.LocalPort, &config.RemotePort)
		if err != nil {
			return nil, err
		}
		configs = append(configs, config)
	}
	return configs, nil
}

func getConfigByID(db *sql.DB, id int) (*TunnelConfig, error) {
	var config TunnelConfig
	err := db.QueryRow(
		"SELECT id, name, host_ip, ssh_port, username, auth_method, password, private_key, local_port, remote_port FROM tunnel_configs WHERE id = ?",
		id).Scan(
		&config.ID, &config.Name, &config.HostIP, &config.SSHPort,
		&config.Username, &config.AuthMethod, &config.Password,
		&config.PrivateKey, &config.LocalPort, &config.RemotePort)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

func promptUser(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func getNewConfig() *TunnelConfig {
	config := &TunnelConfig{}
	
	config.Name = promptUser("Enter a name for this configuration: ")
	config.HostIP = promptUser("Enter host IP address: ")
	
	sshPortStr := promptUser("Enter SSH port (default: 22): ")
	if sshPortStr == "" {
		config.SSHPort = 22
	} else {
		port, err := strconv.Atoi(sshPortStr)
		if err != nil {
			log.Fatalf("Invalid SSH port: %v", err)
		}
		config.SSHPort = port
	}

	config.Username = promptUser("Enter username: ")
	
	authMethod := promptUser("Choose authentication method (password/privatekey): ")
	config.AuthMethod = strings.ToLower(authMethod)

	if config.AuthMethod == "password" {
		config.Password = promptUser("Enter password: ")
	} else if config.AuthMethod == "privatekey" {
		config.PrivateKey = promptUser("Enter private key file path: ")
	} else {
		log.Fatal("Invalid authentication method")
	}

	localPortStr := promptUser("Enter local port: ")
	localPort, err := strconv.Atoi(localPortStr)
	if err != nil {
		log.Fatalf("Invalid local port: %v", err)
	}
	config.LocalPort = localPort

	remotePortStr := promptUser("Enter remote port: ")
	remotePort, err := strconv.Atoi(remotePortStr)
	if err != nil {
		log.Fatalf("Invalid remote port: %v", err)
	}
	config.RemotePort = remotePort

	return config
}

func getAuthMethod(config *TunnelConfig) (ssh.AuthMethod, error) {
	if config.AuthMethod == "password" {
		return ssh.Password(config.Password), nil
	}

	privateKeyBytes, err := ioutil.ReadFile(config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return ssh.PublicKeys(signer), nil
}

func createTunnel(config *TunnelConfig) error {
	authMethod, err := getAuthMethod(config)
	if err != nil {
		return err
	}

	sshConfig := &ssh.ClientConfig{
		User: config.Username,
		Auth: []ssh.AuthMethod{
			authMethod,
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	serverAddr := fmt.Sprintf("%s:%d", config.HostIP, config.SSHPort)
	client, err := ssh.Dial("tcp", serverAddr, sshConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to SSH server: %v", err)
	}
	defer client.Close()

	localAddr := fmt.Sprintf("localhost:%d", config.LocalPort)
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		return fmt.Errorf("failed to start local listener: %v", err)
	}
	defer listener.Close()

	fmt.Printf("SSH tunnel established!\n")
	fmt.Printf("Forwarding localhost:%d -> %s:%d\n", config.LocalPort, config.HostIP, config.RemotePort)

	for {
		localConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept local connection: %v", err)
			continue
		}

		go handleConnection(localConn, client, config.RemotePort)
	}
}

func handleConnection(localConn net.Conn, sshClient *ssh.Client, remotePort int) {
	remoteAddr := fmt.Sprintf("localhost:%d", remotePort)
	remoteConn, err := sshClient.Dial("tcp", remoteAddr)
	if err != nil {
		log.Printf("Failed to connect to remote port: %v", err)
		localConn.Close()
		return
	}

	go copyConn(localConn, remoteConn)
	go copyConn(remoteConn, localConn)
}

func copyConn(dst net.Conn, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	_, _ = io.Copy(dst, src)
}

func main() {
	db, err := initDB()
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	var config *TunnelConfig

	fmt.Println("1. Create new SSH tunnel")
	fmt.Println("2. Use existing configuration")
	choice := promptUser("Enter your choice (1/2): ")

	switch choice {
	case "1":
		config = getNewConfig()
		err = saveConfig(db, config)
		if err != nil {
			log.Printf("Failed to save configuration: %v", err)
		}
	case "2":
		configs, err := listConfigs(db)
		if err != nil {
			log.Fatalf("Failed to list configurations: %v", err)
		}
		if len(configs) == 0 {
			log.Fatal("No saved configurations found. Please create a new one.")
		}

		fmt.Println("\nSaved configurations:")
		for _, cfg := range configs {
			fmt.Printf("%d. %s (%s:%d)\n", cfg.ID, cfg.Name, cfg.HostIP, cfg.RemotePort)
		}

		idStr := promptUser("Enter configuration ID: ")
		id, err := strconv.Atoi(idStr)
		if err != nil {
			log.Fatalf("Invalid ID: %v", err)
		}

		config, err = getConfigByID(db, id)
		if err != nil {
			log.Fatalf("Failed to get configuration: %v", err)
		}
	default:
		log.Fatal("Invalid choice")
	}

	// Handle Ctrl+C gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nShutting down SSH tunnel...")
		os.Exit(0)
	}()

	fmt.Println("Establishing SSH tunnel...")
	if err := createTunnel(config); err != nil {
		log.Fatalf("Failed to create tunnel: %v", err)
	}
} 