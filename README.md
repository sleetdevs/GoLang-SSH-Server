# GoLang-SSH-Server

1. After installing on your server simply go to line 18 "serverPort = """ and change it to serverPort = "Yourserverip:sshserverport" and then continue. DO NOT USE LOCAL PORTS USE THE ACTUAL SERVER IP!
2. apt install golang-go
3. go mod init server.go
4. go mod tidy
5. go run server.go
6. SSH into it with whatever ip/port you used in the script.
