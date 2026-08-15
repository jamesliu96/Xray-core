package browser_dialer

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/common/uuid"
)

//go:embed dialer.html
var webpage []byte

type task struct {
	TaskID         string `json:"taskId"` // Unique ID to route the response connection
	Method         string `json:"method"`
	URL            string `json:"url"`
	Extra          any    `json:"extra,omitempty"`
	StreamResponse bool   `json:"streamResponse"`
}

var (
	server      *http.Server
	currentAddr string
	csrfToken   string
	mu          sync.Mutex

	// Single control connection for the active tab
	controlConn *websocket.Conn

	// Registry for in-flight tasks
	pendingTasks map[string]chan *websocket.Conn
)

var upgrader = &websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func Reload() {
	addr := platform.NewEnvFlag(platform.BrowserDialerAddress).GetValue(func() string { return "" })
	mu.Lock()
	defer mu.Unlock()

	if addr == currentAddr && (addr == "" || server != nil) {
		return
	}

	if server != nil {
		server.Close()
		server = nil
	}

	if controlConn != nil {
		controlConn.Close()
		controlConn = nil
	}

	for id, ch := range pendingTasks {
		close(ch)
		delete(pendingTasks, id)
	}

	currentAddr = addr
	if addr != "" {
		token := uuid.New()
		csrfToken = token.String()
		html := bytes.ReplaceAll(webpage, []byte("csrfToken"), []byte(csrfToken))
		pendingTasks = make(map[string]chan *websocket.Conn)

		server = &http.Server{
			Addr: addr,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/websocket" {
					if r.URL.Query().Get("token") != csrfToken {
						w.WriteHeader(http.StatusForbidden)
						return
					}

					// Differentiate connection intent via query params on the single entry point
					if r.URL.Query().Get("taskId") != "" {
						handleDataConnection(w, r)
					} else {
						handleControlConnection(w, r)
					}
				} else {
					w.Header().Set("Access-Control-Allow-Origin", "*")
					w.Write(html)
				}
			}),
		}
		go server.ListenAndServe()
	}
}

func handleControlConnection(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		errors.LogError(context.Background(), "Browser dialer control upgrade error")
		return
	}

	mu.Lock()
	if controlConn != nil {
		mu.Unlock()
		// Another tab is already active. Drop this connection gracefully to trigger standby polling.
		conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "standby"))
		conn.Close()
		return
	}
	controlConn = conn
	mu.Unlock()

	// Block here to monitor the active tab's connection health
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}

	mu.Lock()
	if controlConn == conn {
		controlConn = nil
	}
	mu.Unlock()
	conn.Close()
}

func handleDataConnection(w http.ResponseWriter, r *http.Request) {
	taskID := r.URL.Query().Get("taskId")

	mu.Lock()
	ch, exists := pendingTasks[taskID]
	if !exists {
		mu.Unlock()
		http.Error(w, "invalid or expired taskId", http.StatusNotFound)
		return
	}
	delete(pendingTasks, taskID)
	mu.Unlock()

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		close(ch)
		return
	}
	ch <- conn // Pipe connection back to the waiting dialTask routine
}

func HasBrowserDialer() bool {
	mu.Lock()
	defer mu.Unlock()
	return controlConn != nil
}

type webSocketExtra struct {
	Protocol string `json:"protocol,omitempty"`
}

func DialWS(uri string, ed []byte) (*websocket.Conn, error) {
	task := task{
		Method:         "WS",
		URL:            uri,
		StreamResponse: true,
		Extra: webSocketExtra{
			Protocol: base64.RawURLEncoding.EncodeToString(ed),
		},
	}
	return dialTask(task)
}

type httpExtra struct {
	Referrer string            `json:"referrer,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Cookies  map[string]string `json:"cookies,omitempty"`
}

func httpExtraFromHeadersAndCookies(headers http.Header, cookies []*http.Cookie) *httpExtra {
	if len(headers) == 0 && len(cookies) == 0 {
		return nil
	}

	extra := httpExtra{}
	if referrer := headers.Get("Referer"); referrer != "" {
		extra.Referrer = referrer
		headers.Del("Referer")
	}

	if len(headers) > 0 {
		extra.Headers = make(map[string]string, len(headers))
		for header := range headers {
			extra.Headers[header] = headers.Get(header)
		}
	}

	if len(cookies) > 0 {
		extra.Cookies = make(map[string]string, len(cookies))
		for _, cookie := range cookies {
			extra.Cookies[cookie.Name] = cookie.Value
		}
	}

	return &extra
}

func DialGet(uri string, headers http.Header, cookies []*http.Cookie) (*websocket.Conn, error) {
	task := task{
		Method:         "GET",
		URL:            uri,
		Extra:          httpExtraFromHeadersAndCookies(headers, cookies),
		StreamResponse: true,
	}
	return dialTask(task)
}

func DialPacket(method string, uri string, headers http.Header, cookies []*http.Cookie, payload []byte) error {
	task := task{
		Method:         method,
		URL:            uri,
		Extra:          httpExtraFromHeadersAndCookies(headers, cookies),
		StreamResponse: false,
	}

	conn, err := dialTask(task)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err = conn.WriteMessage(websocket.BinaryMessage, payload); err != nil {
		return err
	}

	return CheckOK(conn)
}

func dialTask(t task) (*websocket.Conn, error) {
	token := uuid.New()
	t.TaskID = token.String()
	data, err := json.Marshal(t)
	if err != nil {
		return nil, err
	}

	mu.Lock()
	if controlConn == nil {
		mu.Unlock()
		return nil, errors.New("browser dialer is offline")
	}

	ch := make(chan *websocket.Conn, 1)
	pendingTasks[t.TaskID] = ch

	err = controlConn.WriteMessage(websocket.TextMessage, data)
	mu.Unlock()

	if err != nil {
		mu.Lock()
		delete(pendingTasks, t.TaskID)
		mu.Unlock()
		return nil, err
	}

	// Block until the specific JS Data task connection arrives
	select {
	case conn, ok := <-ch:
		if !ok || conn == nil {
			return nil, errors.New("failed to establish task data channel")
		}
		if err := CheckOK(conn); err != nil {
			return nil, err
		}
		return conn, nil
	case <-time.After(15 * time.Second):
		mu.Lock()
		delete(pendingTasks, t.TaskID)
		mu.Unlock()
		return nil, errors.New("browser dialer task timeout")
	}
}

func CheckOK(conn *websocket.Conn) error {
	if _, p, err := conn.ReadMessage(); err != nil {
		conn.Close()
		return err
	} else if s := string(p); s != "ok" {
		conn.Close()
		return errors.New("dialer error: " + s)
	}
	return nil
}

func init() {
	platform.RegisterEnvReload(func() error {
		Reload()
		return nil
	})
}
