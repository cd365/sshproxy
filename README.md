## What is sshproxy?

> sshproxy is a tool that uses ssh tunnel to proxy applications that can only be accessed through the server to the client for local access.
> For example: 
> 1. Server local applications.
> 2. Applications that can only be accessed through a certain server.

```bash
./sshproxy -H example.com -P 22 -U hello -F ~/.ssh/id_rsa -h 127.0.0.1 -p 3306 -l 3306

# start with environment variables
SSH_PROXY_HOST=example.com SSH_PROXY_PORT=22 SSH_PROXY_USER=hello SSH_PROXY_PRIVATE_KEY=~/.ssh/id_rsa SSH_PROXY_LOCAL_PORT=3306 SSH_PROXY_TARGET_HOST=127.0.0.1 SSH_PROXY_TARGET_PORT=3306 ./sshproxy
```