//go:build windows
// +build windows

package main

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/gorilla/websocket"
	webview "github.com/jchv/go-webview2"
	"golang.org/x/crypto/ssh"
)

const (
	gwlStyle      = ^uintptr(15)
	swMinimize    = 6
	swMaximize    = 3
	swRestore     = 9
	swPNoMove     = 0x0002
	swPNoSize     = 0x0001
	swPNoZOrder   = 0x0004
	swPFrameChged = 0x0020
	swPShowWindow = 0x0040

	monitorDefaultToNearest = 2

	wmNCLButtonDown = 0x00A1
	htCaption       = 2

	wsCaption     = 0x00C00000
	wsSysMenu     = 0x00080000
	wsMinimizeBox = 0x00020000
	wsMaximizeBox = 0x00010000
	wsThickFrame  = 0x00040000

	cfUnicodeText = 13
)

var (
	user32                = syscall.NewLazyDLL("user32.dll")
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	procGetWindowLongPtr  = user32.NewProc("GetWindowLongPtrW")
	procSetWindowLongPtr  = user32.NewProc("SetWindowLongPtrW")
	procSetWindowPos      = user32.NewProc("SetWindowPos")
	procShowWindow        = user32.NewProc("ShowWindow")
	procGetWindowRect     = user32.NewProc("GetWindowRect")
	procGetSystemMetrics  = user32.NewProc("GetSystemMetrics")
	procAdjustWindowRect  = user32.NewProc("AdjustWindowRect")
	procMonitorFromWindow = user32.NewProc("MonitorFromWindow")
	procGetMonitorInfo    = user32.NewProc("GetMonitorInfoW")
	procReleaseCapture    = user32.NewProc("ReleaseCapture")
	procSendMessage       = user32.NewProc("SendMessageW")
	procDestroyWindow     = user32.NewProc("DestroyWindow")
	procOpenClipboard     = user32.NewProc("OpenClipboard")
	procCloseClipboard    = user32.NewProc("CloseClipboard")
	procGetClipboardData  = user32.NewProc("GetClipboardData")
	procGlobalLock        = kernel32.NewProc("GlobalLock")
	procGlobalUnlock      = kernel32.NewProc("GlobalUnlock")
)

//go:embed static/index.html
var indexHTML []byte

//go:embed static/vendor/*
var staticAssets embed.FS

type config struct {
	addr  string
	token string
}

type sshLogin struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Rows     int    `json:"rows"`
	Cols     int    `json:"cols"`
}

type savedAccount struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type safeConn struct {
	*websocket.Conn
	mu sync.Mutex
}

type windowRect struct {
	Left   int32
	Top    int32
	Right  int32
	Bottom int32
}

type monitorInfo struct {
	Size    uint32
	Monitor windowRect
	Work    windowRect
	Flags   uint32
}

var (
	windowMaximized bool
	windowRestore   windowRect
)

func (c *safeConn) writeText(msg string) {
	_ = c.write([]byte(msg))
}

func (c *safeConn) write(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.WriteMessage(websocket.TextMessage, data)
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func main() {
	cfg := config{}
	openOnStart := false
	flag.StringVar(&cfg.addr, "addr", "127.0.0.1:2930", "HTTP listen address")
	flag.StringVar(&cfg.token, "token", "", "optional access token")
	flag.BoolVar(&openOnStart, "open", false, "open the app in an isolated browser-engine window")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/", serveIndex(cfg))
	mux.HandleFunc("/ws", serveShell(cfg))
	mux.HandleFunc("/accounts", serveAccounts(cfg))
	mux.Handle("/static/", http.FileServer(http.FS(staticAssets)))
	if vendorAssets, err := fs.Sub(staticAssets, "static/vendor"); err == nil {
		mux.Handle("/vendor/", http.StripPrefix("/vendor/", http.FileServer(http.FS(vendorAssets))))
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	server := &http.Server{
		Addr:              cfg.addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	appURL := appURL(cfg)
	listener, err := net.Listen("tcp", cfg.addr)
	if err != nil {
		if openOnStart {
			runAppWindow(appURL)
			return
		}
		log.Fatal(err)
	}
	defer listener.Close()

	log.Printf("web shell listening on %s", appURL)
	if cfg.token != "" {
		log.Printf("access token enabled")
	}
	if openOnStart {
		go func() {
			if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
				log.Printf("server stopped: %v", err)
			}
		}()
		runAppWindow(appURL)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		_ = server.Close()
		return
	}
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func appURL(cfg config) string {
	u := "http://" + cfg.addr + "/"
	if cfg.token != "" {
		u += "?token=" + url.QueryEscape(cfg.token)
	}
	return u
}

func serveIndex(cfg config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if !authorized(r, cfg.token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		_, _ = w.Write(indexHTML)
	}
}

func serveShell(cfg config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, cfg.token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("mode") != "ssh" {
			http.Error(w, "only ssh mode is enabled", http.StatusBadRequest)
			return
		}

		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("websocket upgrade failed: %v", err)
			return
		}
		conn := &safeConn{Conn: ws}
		defer conn.Close()

		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		serveSSHShell(ctx, conn)
	}
}

func serveAccounts(cfg config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, cfg.token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		switch r.Method {
		case http.MethodGet:
			accounts, err := loadSavedAccounts()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(accounts)
		case http.MethodPost:
			defer r.Body.Close()
			accounts := []savedAccount{}
			if err := json.NewDecoder(r.Body).Decode(&accounts); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := saveSavedAccounts(accounts); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func loadSavedAccounts() ([]savedAccount, error) {
	data, err := os.ReadFile(accountsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return []savedAccount{}, nil
		}
		return nil, err
	}
	accounts := []savedAccount{}
	if err := json.Unmarshal(data, &accounts); err != nil {
		return nil, err
	}
	migrationNeeded, err := decryptSavedAccountPasswords(accounts)
	if err != nil {
		return nil, err
	}
	if migrationNeeded {
		if err := saveSavedAccounts(accounts); err != nil {
			return nil, fmt.Errorf("migrate saved passwords to Windows DPAPI: %w", err)
		}
	}
	sortSavedAccounts(accounts)
	return accounts, nil
}

func saveSavedAccounts(accounts []savedAccount) error {
	path := accountsPath()
	if err := ensureWritableDir(filepath.Dir(path)); err != nil {
		return err
	}
	sortSavedAccounts(accounts)
	encryptedAccounts, err := encryptSavedAccountPasswords(accounts)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(encryptedAccounts, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func sortSavedAccounts(accounts []savedAccount) {
	sort.SliceStable(accounts, func(i, j int) bool {
		left := strings.ToLower(accountSortName(accounts[i]))
		right := strings.ToLower(accountSortName(accounts[j]))
		if left == right {
			return accounts[i].Host < accounts[j].Host
		}
		return left < right
	})
}

func accountSortName(account savedAccount) string {
	name := strings.TrimSpace(account.Name)
	if name != "" {
		return name
	}
	port := strings.TrimSpace(account.Port)
	if port == "" {
		port = "22"
	}
	return strings.TrimSpace(account.Username) + "@" + strings.TrimSpace(account.Host) + ":" + port
}

func accountsPath() string {
	if exePath, err := os.Executable(); err == nil {
		dir := filepath.Join(filepath.Dir(exePath), "data")
		if ensureWritableDir(dir) == nil {
			return filepath.Join(dir, "accounts.json")
		}
	}
	base := os.Getenv("LocalAppData")
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "mshell", "accounts.json")
}

func serveSSHShell(ctx context.Context, conn *safeConn) {
	_, data, err := conn.ReadMessage()
	if err != nil {
		conn.writeText(fmt.Sprintf("\r\nfailed to read ssh login: %v\r\n", err))
		return
	}

	login := sshLogin{}
	if err := json.Unmarshal(data, &login); err != nil {
		conn.writeText(fmt.Sprintf("\r\ninvalid ssh login: %v\r\n", err))
		return
	}

	host := strings.TrimSpace(login.Host)
	port := strings.TrimSpace(login.Port)
	username := strings.TrimSpace(login.Username)
	if port == "" {
		port = "22"
	}
	if host == "" || username == "" {
		conn.writeText("\r\nmissing ssh host or username\r\n")
		return
	}
	if _, err := strconv.Atoi(port); err != nil {
		conn.writeText("\r\ninvalid ssh port\r\n")
		return
	}

	hostKeyCallback, err := verifiedHostKeyCallback()
	if err != nil {
		conn.writeText(fmt.Sprintf("\r\nfailed to initialize SSH host key verification: %v\r\n", err))
		return
	}

	clientConfig := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(login.Password),
		},
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort(host, port), clientConfig)
	if err != nil {
		conn.writeText(fmt.Sprintf("\r\nssh connect failed: %v\r\n", err))
		return
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		conn.writeText(fmt.Sprintf("\r\nssh session failed: %v\r\n", err))
		return
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		conn.writeText(fmt.Sprintf("\r\nfailed to open ssh stdin: %v\r\n", err))
		return
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		conn.writeText(fmt.Sprintf("\r\nfailed to open ssh stdout: %v\r\n", err))
		return
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		conn.writeText(fmt.Sprintf("\r\nfailed to open ssh stderr: %v\r\n", err))
		return
	}

	rows := login.Rows
	if rows <= 0 {
		rows = 30
	}
	cols := login.Cols
	if cols <= 0 {
		cols = 120
	}
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		conn.writeText(fmt.Sprintf("\r\nfailed to request pty: %v\r\n", err))
		return
	}
	if err := session.Shell(); err != nil {
		conn.writeText(fmt.Sprintf("\r\nfailed to start ssh shell: %v\r\n", err))
		return
	}
	conn.writeText(fmt.Sprintf("\r\nconnected to %s@%s:%s\r\n", username, host, port))

	go pipeOutput(conn, stdout)
	go pipeOutput(conn, stderr)

	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		defer stdin.Close()
		for {
			msgType, data, err := conn.ReadMessage()
			if err != nil {
				_ = client.Close()
				return
			}
			if msgType != websocket.TextMessage && msgType != websocket.BinaryMessage {
				continue
			}
			if _, err := stdin.Write(data); err != nil {
				_ = client.Close()
				return
			}
		}
	}()

	waitDone := make(chan error, 1)
	go func() {
		waitDone <- session.Wait()
	}()

	select {
	case <-ctx.Done():
		_ = client.Close()
		<-waitDone
	case err := <-waitDone:
		if err != nil && err != io.EOF {
			conn.writeText(fmt.Sprintf("\r\nssh shell exited: %v\r\n", err))
		} else {
			conn.writeText("\r\nssh shell exited\r\n")
		}
	case <-inputDone:
		_ = client.Close()
		<-waitDone
	}
}

func pipeOutput(conn *safeConn, r io.Reader) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if writeErr := conn.write(buf[:n]); writeErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func authorized(r *http.Request, token string) bool {
	if token == "" {
		return true
	}
	got := r.URL.Query().Get("token")
	if got == "" {
		if value := r.Header.Get("Authorization"); strings.HasPrefix(value, "Bearer ") {
			got = strings.TrimPrefix(value, "Bearer ")
		}
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

func runAppWindow(target string) {
	width, height := initialWindowSize()
	w := webview.NewWithOptions(webview.WebViewOptions{
		DataPath:  webviewDataDir(),
		AutoFocus: true,
		WindowOptions: webview.WindowOptions{
			Title:  "Mshell",
			Width:  width,
			Height: height,
			Center: true,
		},
	})
	if w == nil {
		log.Print("WebView2 runtime is unavailable")
		return
	}
	defer w.Destroy()
	hwnd := uintptr(w.Window())
	makeFrameless(hwnd)
	_ = w.Bind("windowDrag", func() error {
		startWindowDrag(hwnd)
		return nil
	})
	_ = w.Bind("windowMinimize", func() error {
		showWindow(hwnd, swMinimize)
		return nil
	})
	_ = w.Bind("windowToggleMaximize", func() error {
		toggleMaximize(hwnd)
		return nil
	})
	_ = w.Bind("openMsftpShortcut", func(payload string) error {
		return openMsftpShortcut(payload)
	})
	_ = w.Bind("windowClose", func() error {
		destroyWindow(hwnd)
		w.Terminate()
		return nil
	})
	_ = w.Bind("readClipboardText", func() string {
		text, err := readClipboardText(hwnd)
		if err != nil {
			log.Printf("read clipboard failed: %v", err)
			return ""
		}
		return text
	})
	w.Navigate(target)
	w.Run()
}

func readClipboardText(hwnd uintptr) (string, error) {
	if ok, _, err := procOpenClipboard.Call(hwnd); ok == 0 {
		return "", err
	}
	defer procCloseClipboard.Call()

	handle, _, err := procGetClipboardData.Call(cfUnicodeText)
	if handle == 0 {
		return "", err
	}
	ptr, _, err := procGlobalLock.Call(handle)
	if ptr == 0 {
		return "", err
	}
	defer procGlobalUnlock.Call(handle)

	u16 := make([]uint16, 0, 256)
	for offset := uintptr(0); ; offset += unsafe.Sizeof(uint16(0)) {
		ch := *(*uint16)(unsafe.Pointer(ptr + offset))
		if ch == 0 {
			break
		}
		u16 = append(u16, ch)
	}
	return syscall.UTF16ToString(u16), nil
}

func initialWindowSize() (uint, uint) {
	screenWidth, _, _ := procGetSystemMetrics.Call(0)
	screenHeight, _, _ := procGetSystemMetrics.Call(1)
	if screenWidth == 0 || screenHeight == 0 {
		return 1280, 810
	}
	return uint(screenWidth * 2 / 3), uint(screenHeight * 3 / 4)
}

func makeFrameless(hwnd uintptr) {
	style, _, _ := procGetWindowLongPtr.Call(hwnd, gwlStyle)
	style &^= uintptr(wsCaption)
	style |= uintptr(wsSysMenu | wsMinimizeBox | wsMaximizeBox | wsThickFrame)
	procSetWindowLongPtr.Call(hwnd, gwlStyle, style)
	procSetWindowPos.Call(hwnd, 0, 0, 0, 0, 0, swPNoMove|swPNoSize|swPNoZOrder|swPFrameChged)
}

func startWindowDrag(hwnd uintptr) {
	if windowMaximized {
		return
	}
	procReleaseCapture.Call()
	procSendMessage.Call(hwnd, wmNCLButtonDown, htCaption, 0)
}

func showWindow(hwnd uintptr, command int) {
	procShowWindow.Call(hwnd, uintptr(command))
}

func toggleMaximize(hwnd uintptr) {
	if windowMaximized {
		setResizableFrame(hwnd, true)
		setWindowRect(hwnd, windowRestore)
		windowMaximized = false
		return
	}
	if !getWindowRect(hwnd, &windowRestore) {
		return
	}
	work, ok := monitorWorkArea(hwnd)
	if !ok {
		showWindow(hwnd, swMaximize)
		return
	}
	setResizableFrame(hwnd, false)
	setWindowRect(hwnd, work)
	windowMaximized = true
}

func getWindowRect(hwnd uintptr, rect *windowRect) bool {
	ok, _, _ := procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(rect)))
	return ok != 0
}

func setResizableFrame(hwnd uintptr, enabled bool) {
	style, _, _ := procGetWindowLongPtr.Call(hwnd, gwlStyle)
	if enabled {
		style |= uintptr(wsThickFrame)
	} else {
		style &^= uintptr(wsThickFrame)
	}
	procSetWindowLongPtr.Call(hwnd, gwlStyle, style)
	procSetWindowPos.Call(hwnd, 0, 0, 0, 0, 0, swPNoMove|swPNoSize|swPNoZOrder|swPFrameChged)
}

func setWindowRect(hwnd uintptr, rect windowRect) {
	procSetWindowPos.Call(
		hwnd,
		0,
		uintptr(rect.Left),
		uintptr(rect.Top),
		uintptr(rect.Right-rect.Left),
		uintptr(rect.Bottom-rect.Top),
		swPNoZOrder|swPShowWindow|swPFrameChged,
	)
}

func monitorWorkArea(hwnd uintptr) (windowRect, bool) {
	monitor, _, _ := procMonitorFromWindow.Call(hwnd, monitorDefaultToNearest)
	if monitor == 0 {
		return windowRect{}, false
	}
	info := monitorInfo{Size: uint32(unsafe.Sizeof(monitorInfo{}))}
	ok, _, _ := procGetMonitorInfo.Call(monitor, uintptr(unsafe.Pointer(&info)))
	if ok == 0 {
		return windowRect{}, false
	}
	return info.Work, true
}

func destroyWindow(hwnd uintptr) {
	procDestroyWindow.Call(hwnd)
}

func openMsftpShortcut(payload string) error {
	args := []string{"-open"}
	if payload = strings.TrimSpace(payload); payload != "" && payload != "null" && payload != "{}" {
		args = append(args, "-autoconnect", base64.RawURLEncoding.EncodeToString([]byte(payload)))
	}

	if exePath, err := myFTPExecutablePath(); err == nil {
		cmd := exec.Command(exePath, args...)
		cmd.Dir = filepath.Dir(exePath)
		return cmd.Start()
	}

	target := myFTPShortcutPath()
	if _, err := os.Stat(target); err != nil {
		return err
	}
	return exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", target).Start()
}

func myFTPExecutablePath() (string, error) {
	if exePath, err := os.Executable(); err == nil {
		target := filepath.Join(filepath.Dir(exePath), "msftp.exe")
		if fileExists(target) {
			return target, nil
		}
	}
	return "", os.ErrNotExist
}

func myFTPShortcutPath() string {
	if exePath, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exePath), "msftp.lnk")
	}
	return filepath.Join(".", "msftp.lnk")
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func webviewDataDir() string {
	if exePath, err := os.Executable(); err == nil {
		dir := filepath.Join(filepath.Dir(exePath), "data", "WebView2Profile-mshell-v3")
		if ensureWritableDir(dir) == nil {
			return dir
		}
	}

	base := os.Getenv("LocalAppData")
	if base == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "mshell", "WebView2Profile-mshell-v3")
	_ = ensureWritableDir(dir)
	return dir
}

func ensureWritableDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	probe, err := os.CreateTemp(dir, ".write-test-*")
	if err != nil {
		return err
	}
	name := probe.Name()
	if err := probe.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	return os.Remove(name)
}
