package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/cd365/logger/v8"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
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

	// KnownHostsFilePath ssh known_hosts file.
	KnownHostsFilePath string
}

// SshProxy represents the SSH proxy server.
type SshProxy struct {
	Cfg *SshCfg
}

// Start starts the SSH proxy server.
func (proxy *SshProxy) Start(ctx context.Context, serviceServeAddress string, localListenAddress string) error {
	// Create SSH client configuration.
	clientConfig, err := proxy.sshClientConfig()
	if err != nil {
		return fmt.Errorf("failed to create ssh client config: %v", err)
	}

	// Start local TCP listener.
	listener, err := net.Listen("tcp", localListenAddress)
	if err != nil {
		return fmt.Errorf("failed to start local listener: %v", err)
	}
	defer func() { _ = listener.Close() }()

	logger.Info().Msg(fmt.Sprintf("ssh proxy server started. listening on %s ...", localListenAddress))

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
			logger.Error().Msg(fmt.Sprintf("failed to accept local connection: %s", err.Error()))
			continue
		}

		// Dial SSH server.
		sshConn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", proxy.Cfg.Host, proxy.Cfg.Port), clientConfig)
		if err != nil {
			logger.Error().Msg(fmt.Sprintf("failed to dial ssh server: %s", err.Error()))
			_ = localConn.Close()
			continue
		}

		// Dial remote host through SSH tunnel.
		serveConn, err := sshConn.Dial("tcp", serviceServeAddress)
		if err != nil {
			logger.Error().Msg(fmt.Sprintf("failed to dial remote host: %s", err.Error()))
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
	cfg := &ssh.ClientConfig{
		User:    proxy.Cfg.User,
		Auth:    make([]ssh.AuthMethod, 0, 2),
		Timeout: 30 * time.Second,
	}

	// Use password authentication if provided.
	if proxy.Cfg.Password != "" {
		cfg.Auth = append(cfg.Auth, ssh.Password(proxy.Cfg.Password))
	}

	// Use private key authentication if provided.
	if len(proxy.Cfg.PrivateKey) > 0 {
		key, err := ssh.ParsePrivateKey(proxy.Cfg.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %v", err)
		}

		cfg.Auth = append(cfg.Auth, ssh.PublicKeys(key))
	}

	if proxy.Cfg.KnownHostsFilePath != "" {
		hostKeyCallback, err := knownhosts.New(proxy.Cfg.KnownHostsFilePath) /* ~/.ssh/known_hosts */
		if err != nil {
			return nil, fmt.Errorf("failed to parse known_hosts: %s", err.Error())
		}
		cfg.HostKeyCallback = hostKeyCallback
	}

	return cfg, nil
}

const (
	SshProxyServiceHost            = "SSH_PROXY_SERVICE_HOST"              // SSH服务主机地址
	SshProxyServicePort            = "SSH_PROXY_SERVICE_PORT"              // SSH服务主机端口
	SshProxyServiceUser            = "SSH_PROXY_SERVICE_USER"              // SSH服务用户名
	SshProxyServicePass            = "SSH_PROXY_SERVICE_PASS"              // SSH服务用户密码
	SshProxyServiceLocalPrivateKey = "SSH_PROXY_SERVICE_LOCAL_PRIVATE_KEY" // 本机SSH私钥
	SshProxyServiceLocalKnownHosts = "SSH_PROXY_SERVICE_LOCAL_KNOWN_HOSTS" // 本机SSH known_hosts 文件 (用于校验远程服务器的公钥, 防止中间人攻击)
	SshProxyServiceServeAddress    = "SSH_PROXY_SERVICE_SERVE_ADDRESS"     // 待暴露SSH服务器的应用
	SshProxyServiceLocalAddress    = "SSH_PROXY_SERVICE_LOCAL_ADDRESS"     // 暴露到本地的监听地址
)

var (
	daemon      bool   // background process run this program
	debug       bool   // run in debug mode
	pprofListen string // pprof listen address

	sshProxyServiceHost         = "" // ssh service host
	sshProxyServicePort         = 0  // ssh service port
	sshProxyServiceUser         = "" // ssh service username
	sshProxyServicePass         = "" // ssh service password of username
	sshProxyServiceServeAddress = "" // serve address (host + port)

	sshProxyServiceLocalPrivateKey = "" // ssh service private key ~/.ssh/id_rsa
	sshProxyServiceLocalKnownHosts = "" // ssh service private key ~/.ssh/known_hosts
	sshProxyServiceLocalAddress    = "" // local listen address (host + port)
)

func main() {

	userHomeDir, _ := os.UserHomeDir()
	pathLocalPrivateKey := ""
	pathLocalKnownHosts := ""
	if userHomeDir != "" {
		pathLocalPrivateKey = path.Join(userHomeDir, ".ssh", "id_rsa")
		pathLocalKnownHosts = path.Join(userHomeDir, ".ssh", "known_hosts")
	}

	flag.BoolVar(&debug, "e", false, "run in debug mode")
	flag.StringVar(&pprofListen, "x", ":12321", "debug listen address")

	// remote server
	flag.StringVar(&sshProxyServiceHost, "H", "192.168.0.1", "ssh server host; "+SshProxyServiceHost)
	flag.IntVar(&sshProxyServicePort, "P", 22, "ssh server port; "+SshProxyServicePort)
	flag.StringVar(&sshProxyServiceUser, "U", "root", "ssh server username; "+SshProxyServiceUser)
	flag.StringVar(&sshProxyServicePass, "W", "", "password for ssh server username; "+SshProxyServicePass)
	flag.StringVar(&sshProxyServiceServeAddress, "s", "127.0.0.1:1080", "serve address; "+SshProxyServiceServeAddress)
	flag.StringVar(&sshProxyServiceLocalPrivateKey, "F", pathLocalPrivateKey, "local ssh private key for ssh username; "+SshProxyServiceLocalPrivateKey)
	flag.StringVar(&sshProxyServiceLocalKnownHosts, "K", pathLocalKnownHosts, "local ssh known_hosts; "+SshProxyServiceLocalKnownHosts)

	// local exposure
	flag.StringVar(&sshProxyServiceLocalAddress, "l", "127.0.0.1:1081", "local listen port; "+SshProxyServiceLocalAddress)

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
		if tmp := os.Getenv(SshProxyServiceServeAddress); tmp != "" {
			sshProxyServiceServeAddress = tmp
		}
		if tmp := os.Getenv(SshProxyServiceLocalPrivateKey); tmp != "" {
			sshProxyServiceLocalPrivateKey = tmp
		}
		if tmp := os.Getenv(SshProxyServiceLocalKnownHosts); tmp != "" {
			sshProxyServiceLocalKnownHosts = tmp
		}
		if tmp := os.Getenv(SshProxyServiceLocalAddress); tmp != "" {
			sshProxyServiceLocalAddress = tmp
		}
	}

	{
		if debug {
			logger.Default().SetLevel(zerolog.TraceLevel)
			logger.Default().CustomContext(func(ctx zerolog.Context) zerolog.Logger {
				return ctx.Caller().Logger()
			})
		} else {
			logger.Default().SetLevel(zerolog.Disabled)
		}
	}

	// SSH server configure
	cfg := &SshCfg{
		Host:       sshProxyServiceHost,
		Port:       sshProxyServicePort,
		User:       sshProxyServiceUser,
		Password:   sshProxyServicePass, // or leave empty if using private key authentication.
		PrivateKey: nil,                 // specify private key bytes if using private key authentication.
	}

	if sshProxyServiceLocalPrivateKey != "" {
		statPrivateKey, errPrivateKey := os.Stat(sshProxyServiceLocalPrivateKey)
		if errPrivateKey == nil && !statPrivateKey.IsDir() {
			privateKey, errRead := os.ReadFile(sshProxyServiceLocalPrivateKey)
			if errRead == nil {
				cfg.PrivateKey = privateKey
			}
		}
	}

	statKnownHosts, errKnownHosts := os.Stat(sshProxyServiceLocalKnownHosts)
	if errKnownHosts == nil && !statKnownHosts.IsDir() {
		cfg.KnownHostsFilePath = sshProxyServiceLocalKnownHosts
	}

	if cfg.PrivateKey == nil && cfg.Password == "" {
		fmt.Println("Please set ssh private key or password")
		return
	}

	// password first
	if cfg.PrivateKey != nil && cfg.Password != "" {
		cfg.PrivateKey = nil
	}

	if cfg.PrivateKey != nil {
		if cfg.KnownHostsFilePath == "" {
			fmt.Println("Please set ssh known_hosts")
			return
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
			err := proxy.Start(ctx, sshProxyServiceServeAddress, sshProxyServiceLocalAddress)
			if err != nil {
				logger.Error().Msg(fmt.Sprintf("failed to start ssh proxy server: %v", err))
				stop(err)
			}
		}()
	}

	if debug {
		go func() {
			if err := http.ListenAndServe(pprofListen, nil); err != nil {
				stop(err)
			}
		}()
	}

	<-shutdown
}
