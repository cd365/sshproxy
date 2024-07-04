package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/cd365/logger/v3"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"strconv"
	"sync"
	"syscall"
)

// SSHConfig represents SSH server configuration.
type SSHConfig struct {
	Host string
	Port int
	User string
	// Password authentication.
	Password string
	// Private key authentication.
	PrivateKey []byte
}

// SSHProxy represents the SSH proxy server.
type SSHProxy struct {
	Config *SSHConfig
}

// Start starts the SSH proxy server.
func (proxy *SSHProxy) Start(ctx context.Context, localPort int, remoteHost string, remotePort int) error {
	// Create SSH client configuration.
	sshConfig, err := proxy.getClientConfig()
	if err != nil {
		return fmt.Errorf("failed to create SSH client config: %v", err)
	}

	// Start local TCP listener.
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", localPort))
	if err != nil {
		return fmt.Errorf("failed to start local listener: %v", err)
	}
	defer listener.Close()

	logger.Info(fmt.Sprintf("SSH proxy server started. Listening on port %d...", localPort))

	ok := true
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		}
		ok = false
	}()

	// Handle incoming connections.
	for ok {
		localConn, err := listener.Accept()
		if err != nil {
			logger.Error(fmt.Sprintf("failed to accept local connection: %s", err.Error()))
			continue
		}

		// Dial SSH server.
		sshConn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", proxy.Config.Host, proxy.Config.Port), sshConfig)
		if err != nil {
			logger.Error(fmt.Sprintf("failed to dial SSH server: %s", err.Error()))
			localConn.Close()
			continue
		}

		// Dial remote host through SSH tunnel.
		remoteConn, err := sshConn.Dial("tcp", fmt.Sprintf("%s:%d", remoteHost, remotePort))
		if err != nil {
			logger.Error(fmt.Sprintf("failed to dial remote host: %s", err.Error()))
			localConn.Close()
			sshConn.Close()
			continue
		}

		// Start data transfer between local and remote connections.
		go proxy.transferData(localConn, remoteConn)
		go proxy.transferData(remoteConn, localConn)
	}
	return nil
}

// transferData transfers data between local and remote connections.
func (proxy *SSHProxy) transferData(src, dst net.Conn) {
	defer src.Close()
	defer dst.Close()
	io.Copy(src, dst)
}

// getClientConfig creates SSH client configuration based on SSHConfig.
func (proxy *SSHProxy) getClientConfig() (*ssh.ClientConfig, error) {
	var authMethods []ssh.AuthMethod

	// Use password authentication if provided.
	if proxy.Config.Password != "" {
		authMethods = append(authMethods, ssh.Password(proxy.Config.Password))
	}

	// Use private key authentication if provided.
	if len(proxy.Config.PrivateKey) > 0 {
		key, err := ssh.ParsePrivateKey(proxy.Config.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %v", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(key))
	}

	return &ssh.ClientConfig{
		User: proxy.Config.User,
		Auth: authMethods,
		// Disable host key checking. In a real application, you should verify the host key.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}, nil
}

var (
	daemon bool // background process run this program
	debug  bool // run in debug mode

	sshHost       = "" // ssh host
	sshPort       = 0  // ssh port
	sshUser       = "" // ssh username
	sshPass       = "" // ssh username.password
	sshPrivateKey = "" // ssh private key ~/.ssh/id_rsa

	localPort  = 0  // local listen port
	targetHost = "" // target host
	targetPort = 0  // target port
)

func main() {
	flag.BoolVar(&debug, "D", false, "run in debug mode")

	flag.StringVar(&sshHost, "H", "", "ssh server host; SSH_PROXY_HOST")
	flag.IntVar(&sshPort, "P", 22, "ssh server port; SSH_PROXY_PORT")
	flag.StringVar(&sshUser, "U", "root", "ssh username; SSH_PROXY_USER")
	flag.StringVar(&sshPass, "W", "", "password for ssh username; SSH_PROXY_PASS")
	flag.StringVar(&sshPrivateKey, "F", "", "private key for ssh username; SSH_PROXY_PRIVATE_KEY")

	flag.BoolVar(&daemon, "d", false, "background process run this program use -d")

	flag.IntVar(&localPort, "l", 3306, "local listen port; SSH_PROXY_LOCAL_PORT")
	flag.StringVar(&targetHost, "h", "127.0.0.1", "target host; SSH_PROXY_TARGET_HOST")
	flag.IntVar(&targetPort, "p", 3306, "target port; SSH_PROXY_TARGET_PORT")
	flag.Parse()

	if daemon {
		args := os.Args[1:]
		length := len(args)
		for i := 0; i < length; i++ {
			if args[i] == "-d" {
				args[i] = "-d=false"
				break
			}
		}
		cmd := exec.Command(os.Args[0], args...)
		if err := cmd.Start(); err != nil {
			fmt.Println(err.Error())
			return
		}
		fmt.Println("pid", cmd.Process.Pid)
		return
	}

	{
		// Prioritize using environment variables to configure values.
		if tmp := os.Getenv("SSH_PROXY_HOST"); tmp != "" {
			sshHost = tmp
		}
		if tmp := os.Getenv("SSH_PROXY_PORT"); tmp != "" {
			if i64, err := strconv.ParseInt(tmp, 10, 64); err == nil && i64 > 0 && i64 < 1<<16 {
				sshPort = int(i64)
			}
		}
		if tmp := os.Getenv("SSH_PROXY_USER"); tmp != "" {
			sshUser = tmp
		}
		if tmp := os.Getenv("SSH_PROXY_PASS"); tmp != "" {
			sshPass = tmp
		}
		if tmp := os.Getenv("SSH_PROXY_PRIVATE_KEY"); tmp != "" {
			sshPrivateKey = tmp
		}
		if tmp := os.Getenv("SSH_PROXY_LOCAL_PORT"); tmp != "" {
			if i64, err := strconv.ParseInt(tmp, 10, 64); err == nil && i64 > 0 && i64 < 1<<16 {
				localPort = int(i64)
			}
		}
		if tmp := os.Getenv("SSH_PROXY_TARGET_HOST"); tmp != "" {
			targetHost = tmp
		}
		if tmp := os.Getenv("SSH_PROXY_TARGET_PORT"); tmp != "" {
			if i64, err := strconv.ParseInt(tmp, 10, 64); err == nil && i64 > 0 && i64 < 1<<16 {
				targetPort = int(i64)
			}
		}
	}

	{
		if debug {
			logger.DefaultLogger.HandlerOptions.AddSource = true
			logger.DefaultLogger.LevelVar.Set(logger.LevelAll)
		} else {
			logger.DefaultLogger.HandlerOptions.AddSource = false
			logger.DefaultLogger.LevelVar.Set(logger.LevelOff)
		}
	}

	// SSH server configuration
	sshConfig := &SSHConfig{
		Host:       sshHost,
		Port:       sshPort,
		User:       sshUser,
		Password:   sshPass, // or leave empty if using private key authentication.
		PrivateKey: nil,     // specify private key bytes if using private key authentication.
	}

	if sshPrivateKey == "" {
		if currentUserHomeDir, err := os.UserHomeDir(); err == nil {
			currentUserSshPrivateKey := path.Join(currentUserHomeDir, ".ssh", "id_rsa")
			if stat, fer := os.Stat(currentUserSshPrivateKey); fer == nil && !stat.IsDir() {
				sshPrivateKey = currentUserSshPrivateKey
			}
		}
	}

	if sshPrivateKey != "" {
		if privateKey, err := os.ReadFile(sshPrivateKey); err == nil {
			sshConfig.PrivateKey = privateKey
		}
	}

	// SSH proxy instance
	proxy := &SSHProxy{
		Config: sshConfig,
	}

	wg := &sync.WaitGroup{}
	defer wg.Wait()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	shutdown := make(chan error, 1)
	defer close(shutdown)

	once := &sync.Once{}
	stop := func(err error) { once.Do(func() { shutdown <- err }) }

	{
		wg.Add(1)
		go func() {
			defer wg.Done()

			notify := make(chan os.Signal, 1)
			signal.Notify(notify, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
			select {
			case <-ctx.Done():
			case sig := <-notify:
				stop(fmt.Errorf("%s", sig.String()))
			}
		}()
	}

	{
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Start SSH proxy server
			err := proxy.Start(ctx, localPort, targetHost, targetPort) // localPort, remotePort
			if err != nil {
				logger.Error(fmt.Sprintf("failed to start SSH proxy server: %v", err))
				stop(err)
			}
		}()
	}

	<-shutdown
}
