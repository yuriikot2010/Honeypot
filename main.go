package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	telegramToken  = "tgbottokenhere"
	telegramChatID = "	telegramChatID "
	urlhausAPI     = "urlhausAPI"
	abuseIPDBAPI   = "abuseIPDBAPI"
	logFile        = "honeypot_logs.csv"
	cooldownFile   = "ip_cooldown.db"
	abuseCooldown  = 15 * time.Minute
)

var (
	services = map[int]string{
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		80:    "HTTP",
		443:   "HTTPS",
		3306:  "MySQL",
		3389:  "RDP",
		5432:  "PostgreSQL",
		5900:  "VNC",
		6379:  "Redis",
		8080:  "HTTP-Alt",
		2222:  "SSH-Alt",
	}
	mu            sync.Mutex
	cooldownMap   = make(map[string]time.Time)
	cooldownMutex sync.Mutex
)

type LoginAttempt struct {
	Timestamp  string
	Service    string
	IP         string
	Port       int
	Username   string
	Password   string
	UserAgent  string
	TargetURL  string
	Path       string
}

func main() {
	initLogFile()
	loadCooldownDB()

	var wg sync.WaitGroup
	for port, service := range services {
		wg.Add(1)
		go func(p int, s string) {
			defer wg.Done()
			startListener(p, s)
		}(port, service)
	}

	log.Println("Honeypot running on multiple ports...")
	wg.Wait()
}

func initLogFile() {
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		file, err := os.Create(logFile)
		if err != nil {
			log.Fatalf("Failed to create log file: %v", err)
		}
		writer := csv.NewWriter(file)
		headers := []string{
			"Timestamp", "Service", "IP", "Port", "Username", "Password",
			"UserAgent", "TargetURL", "Path",
		}
		writer.Write(headers)
		writer.Flush()
		file.Close()
	}
}

func loadCooldownDB() {
	if _, err := os.Stat(cooldownFile); os.IsNotExist(err) {
		return
	}

	file, err := os.Open(cooldownFile)
	if err != nil {
		log.Printf("Error opening cooldown file: %v", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "|")
		if len(parts) == 2 {
			timestamp, err := time.Parse(time.RFC3339, parts[1])
			if err == nil {
				if time.Since(timestamp) <= abuseCooldown {
					cooldownMap[parts[0]] = timestamp
				}
			}
		}
	}
}

func saveCooldownDB() {
	file, err := os.Create(cooldownFile)
	if err != nil {
		log.Printf("Error creating cooldown file: %v", err)
		return
	}
	defer file.Close()

	cooldownMutex.Lock()
	defer cooldownMutex.Unlock()

	for ip, timestamp := range cooldownMap {
		if time.Since(timestamp) <= abuseCooldown {
			_, err := file.WriteString(fmt.Sprintf("%s|%s\n", ip, timestamp.Format(time.RFC3339)))
			if err != nil {
				log.Printf("Error writing to cooldown file: %v", err)
			}
		}
	}
}

func isOnCooldown(ip string) bool {
	cooldownMutex.Lock()
	defer cooldownMutex.Unlock()

	if timestamp, exists := cooldownMap[ip]; exists {
		if time.Since(timestamp) <= abuseCooldown {
			return true
		}
		// Remove expired entries
		delete(cooldownMap, ip)
	}
	return false
}

func markAsReported(ip string) {
	cooldownMutex.Lock()
	defer cooldownMutex.Unlock()

	cooldownMap[ip] = time.Now()
	go saveCooldownDB()
}

func startListener(port int, service string) {
	addr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("Failed to start %s listener on port %d: %v", service, port, err)
		return
	}
	defer listener.Close()

	log.Printf("%s honeypot listening on port %d", service, port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting %s connection: %v", service, err)
			continue
		}
		go handleConnection(conn, service, port)
	}
}

func handleConnection(conn net.Conn, service string, port int) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().(*net.TCPAddr).IP.String()

	var username, password string
	var userAgent string
	var targetURL string
	var path string

	switch service {
	case "SSH", "SSH-Alt":
		conn.Write([]byte("SSH-2.0-OpenSSH_7.9p1 Ubuntu-10\r\n"))
		buf := make([]byte, 1024)
		_, err := conn.Read(buf)
		if err != nil {
			return
		}

		conn.Write([]byte("Password: "))
		_, err = conn.Read(buf)
		if err != nil {
			return
		}

		conn.Write([]byte("Permission denied, please try again.\r\nPassword: "))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}

		username = "root"
		password = string(bytes.Trim(buf[:n], "\x00"))

	case "Telnet":
		conn.Write([]byte("Ubuntu 18.04.6 LTS\r\n\r\nLogin: "))
		reader := bufio.NewReader(conn)
		username, _ = reader.ReadString('\n')
		username = strings.TrimSpace(username)
		conn.Write([]byte("Password: "))
		password, _ = reader.ReadString('\n')
		password = strings.TrimSpace(password)
		conn.Write([]byte("\r\nLogin incorrect\r\n"))

	case "FTP":
		conn.Write([]byte("220 FTP Server Ready\r\n"))
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			line = strings.TrimSpace(line)
			if strings.HasPrefix(strings.ToUpper(line), "USER ") {
				username = strings.TrimPrefix(strings.ToUpper(line), "USER ")
				conn.Write([]byte("331 Password required for " + username + "\r\n"))
			} else if strings.HasPrefix(strings.ToUpper(line), "PASS ") {
				password = strings.TrimPrefix(strings.ToUpper(line), "PASS ")
				conn.Write([]byte("530 Login incorrect\r\n"))
				break
			} else {
				conn.Write([]byte("500 Unknown command\r\n"))
			}
		}

	case "HTTP", "HTTPS", "HTTP-Alt":
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}

		request := string(buf[:n])
		lines := strings.Split(request, "\r\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "User-Agent:") {
				userAgent = strings.TrimSpace(strings.TrimPrefix(line, "User-Agent:"))
			}
			if strings.HasPrefix(line, "GET ") || strings.HasPrefix(line, "POST ") {
				parts := strings.Split(line, " ")
				if len(parts) > 1 {
					path = parts[1]
					if strings.Contains(path, ".bin") || strings.Contains(path, ".elf") {
						targetURL = path
					}
				}
			}
		}

		response := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
			"<html><body><h1>Admin Portal</h1></body></html>"
		conn.Write([]byte(response))

	default:
		conn.Write([]byte("Welcome\r\n"))
		buf := make([]byte, 1024)
		conn.Read(buf)
		username = "admin"
		password = "admin"
	}

	attempt := LoginAttempt{
		Timestamp:  time.Now().Format(time.RFC3339),
		Service:    service,
		IP:         remoteAddr,
		Port:       port,
		Username:   username,
		Password:   password,
		UserAgent:  userAgent,
		TargetURL:  targetURL,
		Path:       path,
	}

	logAttempt(attempt)

	if targetURL != "" {
		go submitToURLhaus(targetURL, remoteAddr)
	}

	if !isOnCooldown(remoteAddr) {
		go reportToAbuseIPDB(remoteAddr, service, port, path)
		markAsReported(remoteAddr)
	} else {
		log.Printf("IP %s is on cooldown - skipping AbuseIPDB report", remoteAddr)
	}
}

func logAttempt(attempt LoginAttempt) {
	mu.Lock()
	defer mu.Unlock()

	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Error opening log file: %v", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	err = writer.Write([]string{
		attempt.Timestamp,
		attempt.Service,
		attempt.IP,
		strconv.Itoa(attempt.Port),
		attempt.Username,
		attempt.Password,
		attempt.UserAgent,
		attempt.TargetURL,
		attempt.Path,
	})
	if err != nil {
		log.Printf("Error writing to log file: %v", err)
	}

	message := fmt.Sprintf(
		"🚨 *Suspicious Activity Detected* 🚨\n\n"+
			"*Service:* %s\n"+
			"*Port:* %d\n"+
			"%s"+ // Path if available
			"*Username:* %s\n"+
			"*Password:* %s\n"+
			"*User Agent:* %s\n"+
			"%s", // Target URL if available
		attempt.Service,
		attempt.Port,
		formatPath(attempt.Path),
		attempt.Username,
		attempt.Password,
		attempt.UserAgent,
		formatTargetURL(attempt.TargetURL),
	)

	sendTelegramAlert(message)
}

func formatPath(path string) string {
	if path != "" {
		return fmt.Sprintf("*Path:* %s\n", path)
	}
	return ""
}

func formatTargetURL(url string) string {
	if url != "" {
		return fmt.Sprintf("*Target URL:* %s\n", url)
	}
	return ""
}

func sendTelegramAlert(message string) {
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", telegramToken)
	data := url.Values{
		"chat_id":    {telegramChatID},
		"text":       {message},
		"parse_mode": {"Markdown"},
	}

	_, err := http.PostForm(apiURL, data)
	if err != nil {
		log.Printf("Error sending Telegram alert: %v", err)
	}
}

func submitToURLhaus(targetURL, sourceIP string) {
	apiURL := "https://urlhaus-api.abuse.ch/v1/url/"
	data := map[string]string{
		"token":       urlhausAPI,
		"url":         targetURL,
		"threat":      "malware_download",
		"tags":        "mirai,botnet",
		"reporter":    "mirai_honeypot",
		"source_ip":   sourceIP,
		"source_type": "honeypot",
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Error marshaling URLhaus data: %v", err)
		return
	}

	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Error creating URLhaus request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error submitting to URLhaus: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("URLhaus submission failed: %s - %s", resp.Status, string(body))
		return
	}

	log.Printf("Submitted target URL to URLhaus: %s", targetURL)
}

func reportToAbuseIPDB(ip, service string, port int, path string) {
	apiURL := "https://api.abuseipdb.com/api/v2/report"
	categories := "14,18" // Brute-Force (14) and Port Scan (18)
	
	comment := fmt.Sprintf("Suspicious activity detected on %s service (Port: %d)", service, port)
	if path != "" {
		comment += fmt.Sprintf(", Path: %s", path)
	}

	payload := map[string]string{
		"ip":         ip,
		"categories": categories,
		"comment":    comment,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshaling AbuseIPDB data: %v", err)
		return
	}

	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Error creating AbuseIPDB request: %v", err)
		return
	}

	req.Header.Set("Key", abuseIPDBAPI)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error reporting to AbuseIPDB: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("AbuseIPDB report failed: %s - %s", resp.Status, string(body))
		return
	}

	log.Printf("Reported suspicious activity to AbuseIPDB")
}
