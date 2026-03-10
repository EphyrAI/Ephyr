package broker

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Event is the envelope sent to WebSocket clients on each auditable action.
type Event struct {
	Type      string      `json:"type"`
	Timestamp string      `json:"timestamp"`
	Data      interface{} `json:"data"`
}

// EventHub manages a set of connected WebSocket clients and broadcasts
// events to all of them with backpressure (slow clients get dropped).
type EventHub struct {
	mu      sync.RWMutex
	clients map[*wsClient]struct{}
}

// wsClient is a single WebSocket connection managed by the hub.
type wsClient struct {
	conn *websocket.Conn
	send chan []byte // buffered channel; events dropped when full
}

const (
	wsSendBufSize  = 64
	wsWriteTimeout = 10 * time.Second
	wsPongTimeout  = 60 * time.Second
	wsPingInterval = 30 * time.Second
)

// upgrader allows all origins (dashboard may be served from a different host).
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// NewEventHub creates a ready-to-use EventHub.
func NewEventHub() *EventHub {
	return &EventHub{
		clients: make(map[*wsClient]struct{}),
	}
}

// Broadcast serializes an Event and sends it to every connected client.
// Slow clients whose send buffer is full will have the event dropped
// (non-blocking send).
func (h *EventHub) Broadcast(event Event) {
	if event.Timestamp == "" {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("[ws] marshal event: %v", err)
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	for c := range h.clients {
		select {
		case c.send <- data:
		default:
			// Drop event for slow client.
		}
	}
}

// register adds a client to the hub.
func (h *EventHub) register(c *wsClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[c] = struct{}{}
}

// unregister removes a client from the hub and closes its connection.
func (h *EventHub) unregister(c *wsClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.clients[c]; ok {
		delete(h.clients, c)
		close(c.send)
	}
}

// HandleWebSocket is the HTTP handler for GET /v1/events. It upgrades the
// connection to WebSocket, authenticates via ?token= query parameter, and
// streams events until the client disconnects.
func (h *EventHub) HandleWebSocket(token string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authenticate via query param token.
		if token != "" {
			t := r.URL.Query().Get("token")
			if t != token {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("[ws] upgrade error: %v", err)
			return
		}

		client := &wsClient{
			conn: conn,
			send: make(chan []byte, wsSendBufSize),
		}
		h.register(client)

		// Writer goroutine: reads from send channel and writes to WebSocket.
		go h.writePump(client)
		// Reader goroutine: reads (and discards) client messages, handles pong.
		go h.readPump(client)
	}
}

// writePump sends queued messages to the WebSocket connection and sends
// periodic pings to keep the connection alive.
func (h *EventHub) writePump(c *wsClient) {
	ticker := time.NewTicker(wsPingInterval)
	defer func() {
		ticker.Stop()
		c.conn.Close()
		h.unregister(c)
	}()

	for {
		select {
		case msg, ok := <-c.send:
			if !ok {
				// Channel closed.
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			c.conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// readPump reads and discards messages from the client. It keeps the
// connection alive by responding to ping/pong and detects disconnects.
func (h *EventHub) readPump(c *wsClient) {
	defer func() {
		h.unregister(c)
		c.conn.Close()
	}()

	c.conn.SetReadLimit(512)
	c.conn.SetReadDeadline(time.Now().Add(wsPongTimeout))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(wsPongTimeout))
		return nil
	})

	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			break
		}
	}
}
