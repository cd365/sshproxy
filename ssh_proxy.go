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
	"time"
)

// SshCfg represents SSH server configure.
type SshCfg struct {
	Host string

	Port int

	User string

	// Password authentication.
	Password string

	// Private key authentication.
	PrivateKey []byte
}

// SshProxy represents the SSH proxy server.
type SshProxy struct {
	Cfg *SshCfg
}

// Start starts the SSH proxy server.
func (proxy *SshProxy) Start(ctx context.Context, serviceServeAddress string, localListenPort int) error {
	// Create SSH client configuration.
	clientConfig, err := proxy.sshClientConfig()
	if err != nil {
		return fmt.Errorf("failed to create SSH client config: %v", err)
	}

	// Start local TCP listener.
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", localListenPort))
	if err != nil {
		return fmt.Errorf("failed to start local listener: %v", err)
	}
	defer func() { _ = listener.Close() }()

	logger.Info(fmt.Sprintf("SSH proxy server started. Listening on port %d...", localListenPort))

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
		sshConn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", proxy.Cfg.Host, proxy.Cfg.Port), clientConfig)
		if err != nil {
			logger.Error(fmt.Sprintf("failed to dial SSH server: %s", err.Error()))
			_ = localConn.Close()
			continue
		}

		// Dial remote host through SSH tunnel.
		serveConn, err := sshConn.Dial("tcp", serviceServeAddress)
		if err != nil {
			logger.Error(fmt.Sprintf("failed to dial remote host: %s", err.Error()))
			_ = localConn.Close()
			_ = sshConn.Close()
			continue
		}

		// Start data transfer between local and remote connections.
		go proxy.copy(localConn, serveConn)
		go proxy.copy(serveConn, localConn)
	}
	return nil
}

// transferData transfers data between local and remote connections.
func (proxy *SshProxy) copy(src, dst net.Conn) {
	defer func() { _ = src.Close() }()
	defer func() { _ = dst.Close() }()
	_, _ = io.Copy(src, dst)
}

// sshClientConfig creates SSH client configuration based on SshCfg.
func (proxy *SshProxy) sshClientConfig() (*ssh.ClientConfig, error) {
	authMethods := make([]ssh.AuthMethod, 0, 2)

	// Use password authentication if provided.
	if proxy.Cfg.Password != "" {
		authMethods = append(authMethods, ssh.Password(proxy.Cfg.Password))
	}

	// Use private key authentication if provided.
	if len(proxy.Cfg.PrivateKey) > 0 {
		key, err := ssh.ParsePrivateKey(proxy.Cfg.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %v", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(key))
	}

	return &ssh.ClientConfig{
		User: proxy.Cfg.User,
		Auth: authMethods,
		// Disable host key checking. In a real application, you should verify the host key.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         30 * time.Second,
	}, nil
}

const (
	SshProxyServiceHost       = "SSH_PROXY_SERVICE_HOST"
	SshProxyServicePort       = "SSH_PROXY_SERVICE_PORT"
	SshProxyServiceUser       = "SSH_PROXY_SERVICE_USER"
	SshProxyServicePass       = "SSH_PROXY_SERVICE_PASS"
	SshProxyServicePrivateKey = "SSH_PROXY_SERVICE_PRIVATE_KEY"

	SshProxyServiceServeAddress = "SSH_PROXY_SERVICE_SERVE_ADDRESS"

	SshProxyServiceLocalPort = "SSH_PROXY_SERVICE_LOCAL_PORT"
)

var (
	daemon bool // background process run this program
	debug  bool // run in debug mode

	sshProxyServiceHost       = "" // ssh service host
	sshProxyServicePort       = 0  // ssh service port
	sshProxyServiceUser       = "" // ssh service username
	sshProxyServicePass       = "" // ssh service password of username
	sshProxyServicePrivateKey = "" // ssh service private key ~/.ssh/id_rsa

	sshProxyServiceServeAddress = "" // serve address (host + port)

	sshProxyServiceLocalPort = 0 // local listen port
)

func main() {
	flag.BoolVar(&debug, "e", false, "run in debug mode")

	// remote server
	flag.StringVar(&sshProxyServiceHost, "H", "example.com", "ssh server host; "+SshProxyServiceHost)
	flag.IntVar(&sshProxyServicePort, "P", 22, "ssh server port; "+SshProxyServicePort)
	flag.StringVar(&sshProxyServiceUser, "U", "root", "ssh username; "+SshProxyServiceUser)
	flag.StringVar(&sshProxyServicePass, "W", "", "password for ssh username; "+SshProxyServicePass)
	flag.StringVar(&sshProxyServicePrivateKey, "F", "", "private key for ssh username; "+SshProxyServicePrivateKey)

	flag.StringVar(&sshProxyServiceServeAddress, "s", "127.0.0.1:1080", "serve address; "+SshProxyServiceServeAddress)

	flag.IntVar(&sshProxyServiceLocalPort, "p", 10800, "local listen port; "+SshProxyServiceLocalPort)

	flag.BoolVar(&daemon, "d", false, "background process run this program use -d")
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
		if tmp := os.Getenv(SshProxyServiceHost); tmp != "" {
			sshProxyServiceHost = tmp
		}
		if tmp := os.Getenv(SshProxyServicePort); tmp != "" {
			if i64, err := strconv.ParseInt(tmp, 10, 64); err == nil && i64 > 0 && i64 < 1<<16 {
				sshProxyServicePort = int(i64)
			}
		}
		if tmp := os.Getenv(SshProxyServiceUser); tmp != "" {
			sshProxyServiceUser = tmp
		}
		if tmp := os.Getenv(SshProxyServicePass); tmp != "" {
			sshProxyServicePass = tmp
		}
		if tmp := os.Getenv(SshProxyServicePrivateKey); tmp != "" {
			sshProxyServicePrivateKey = tmp
		}
		if tmp := os.Getenv(SshProxyServiceLocalPort); tmp != "" {
			if i64, err := strconv.ParseInt(tmp, 10, 64); err == nil && i64 > 0 && i64 < 1<<16 {
				sshProxyServiceLocalPort = int(i64)
			}
		}
		if tmp := os.Getenv(SshProxyServiceServeAddress); tmp != "" {
			sshProxyServiceServeAddress = tmp
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
	cfg := &SshCfg{
		Host:       sshProxyServiceHost,
		Port:       sshProxyServicePort,
		User:       sshProxyServiceUser,
		Password:   sshProxyServicePass, // or leave empty if using private key authentication.
		PrivateKey: nil,                 // specify private key bytes if using private key authentication.
	}

	if sshProxyServicePrivateKey == "" {
		if currentUserHomeDir, err := os.UserHomeDir(); err == nil {
			currentUserSshPrivateKey := path.Join(currentUserHomeDir, ".ssh", "id_rsa")
			if stat, fer := os.Stat(currentUserSshPrivateKey); fer == nil && !stat.IsDir() {
				sshProxyServicePrivateKey = currentUserSshPrivateKey
			}
		}
	}

	if sshProxyServicePrivateKey != "" {
		if privateKey, err := os.ReadFile(sshProxyServicePrivateKey); err == nil {
			cfg.PrivateKey = privateKey
		}
	}

	// SSH proxy instance
	proxy := &SshProxy{
		Cfg: cfg,
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
			// start ssh proxy server
			err := proxy.Start(ctx, sshProxyServiceServeAddress, sshProxyServiceLocalPort)
			if err != nil {
				logger.Error(fmt.Sprintf("failed to start SSH proxy server: %v", err))
				stop(err)
			}
		}()
	}

	<-shutdown
}
