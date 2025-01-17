## What is sshproxy?

> sshproxy is a tool that uses ssh tunnel to proxy applications that can only be accessed through the server to the client for local access.
> For example: 
> 1. Server local applications.
> 2. Applications that can only be accessed through a certain server.

```bash
./sshproxy -H example.com -P 22 -U hello -W your-password -s 127.0.0.1:1080 -l 127.0.0.1:1081
./sshproxy -H example.com -P 22 -U hello -F /home/hello/.ssh/id_rsa -K /home/hello/.ssh/known_hosts -s 127.0.0.1:1080 -l 127.0.0.1:1081

# start with environment variables
SSH_PROXY_SERVICE_HOST=example.com SSH_PROXY_SERVICE_PORT=22 SSH_PROXY_SERVICE_USER=hello SSH_PROXY_SERVICE_LOCAL_PRIVATE_KEY=~/.ssh/id_rsa SSH_PROXY_SERVICE_LOCAL_KNOWN_HOSTS=~/.ssh/known_hosts SSH_PROXY_SERVICE_SERVE_ADDRESS=127.0.0.1:1080 SSH_PROXY_SERVICE_LOCAL_ADDRESS=127.0.0.1:1081 ./sshproxy
```