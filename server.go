package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "io"
    "log"
    "net"
    "strings"

    "golang.org/x/crypto/ssh"
)

const (
    serverPort = ""
    username   = "admin"
    password   = "admin"
)

func generatePrivateKey() ([]byte, error) {
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, err
    }
    return pem.EncodeToMemory(&pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(key),
    }), nil
}

func handleSession(channel ssh.Channel, requests <-chan *ssh.Request) {
    go func() {
        for req := range requests {
            switch req.Type {
            case "pty-req":
                req.Reply(true, nil)
            case "shell":
                req.Reply(true, nil)
            default:
                req.Reply(false, nil)
            }
        }
    }()
    for {
        _, err := io.WriteString(channel, "> ")
        if err != nil {
            break
        }
        var cmdBuffer []byte
        for {
            buf := make([]byte, 1)
            n, err := channel.Read(buf)
            if err != nil || n == 0 {
                return
            }
            b := buf[0]
            if b == '\r' || b == '\n' {
                io.WriteString(channel, "\r\n")
                break
            }
            if b == 127 || b == 8 {
                if len(cmdBuffer) > 0 {
                    cmdBuffer = cmdBuffer[:len(cmdBuffer)-1]
                    io.WriteString(channel, "\b \b")
                }
                continue
            }
            io.WriteString(channel, string(b))
            cmdBuffer = append(cmdBuffer, b)
        }
        cmd := strings.TrimSpace(string(cmdBuffer))
        if cmd == "" {
            continue
        }
        switch cmd {
        case "help":
            io.WriteString(channel, "Available commands: help, exit\r\n")
        case "exit":
            io.WriteString(channel, "Goodbye!\r\n")
            channel.Close()
            return
        default:
            io.WriteString(channel, "Unknown command\r\n")
        }
    }
}

func handleConnection(conn net.Conn, config *ssh.ServerConfig) {
    defer conn.Close()
    sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
    if err != nil {
        log.Println("Failed handshake:", err)
        return
    }
    defer sshConn.Close()
    go ssh.DiscardRequests(reqs)
    for newChannel := range chans {
        if newChannel.ChannelType() != "session" {
            newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
            continue
        }
        channel, requests, err := newChannel.Accept()
        if err != nil {
            log.Println("Could not accept channel:", err)
            continue
        }
        go handleSession(channel, requests)
    }
}

func main() {
    privateKeyBytes, err := generatePrivateKey()
    if err != nil {
        log.Fatal("Failed to generate private key:", err)
    }
    privateKey, err := ssh.ParsePrivateKey(privateKeyBytes)
    if err != nil {
        log.Fatal("Failed to parse private key:", err)
    }
    config := &ssh.ServerConfig{
        PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
            if c.User() == username && string(pass) == password {
                return nil, nil
            }
            return nil, fmt.Errorf("invalid credentials")
        },
    }
    config.AddHostKey(privateKey)
    listener, err := net.Listen("tcp", serverPort)
    if err != nil {
        log.Fatal("Failed to listen on", serverPort, err)
    }
    defer listener.Close()
    log.Println("SSH server listening on", serverPort)
    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Println("Failed to accept connection:", err)
            continue
        }
        go handleConnection(conn, config)
    }
}
