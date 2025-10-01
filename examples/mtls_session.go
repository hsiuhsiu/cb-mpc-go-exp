package examples

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// MTLSSession implements the mpc.Session interface using mTLS for secure communication
type MTLSSession struct {
	myIndex    int
	partyCount int

	// Network connections
	listener   net.Listener
	clients    []net.Conn
	clientsMu  sync.RWMutex

	// Message queues for each party
	messageQueues []chan []byte

	// Control
	ctx    context.Context
	cancel context.CancelFunc
	closed bool
	mu     sync.Mutex
}

// NewMTLSSession creates a new mTLS-based session
func NewMTLSSession(myIndex, partyCount int, serverAddr string, clientAddrs []string, tlsConfig *tls.Config) (*MTLSSession, error) {
	ctx, cancel := context.WithCancel(context.Background())

	session := &MTLSSession{
		myIndex:       myIndex,
		partyCount:    partyCount,
		clients:       make([]net.Conn, partyCount),
		messageQueues: make([]chan []byte, partyCount),
		ctx:           ctx,
		cancel:        cancel,
	}

	// Initialize message queues
	for i := 0; i < partyCount; i++ {
		session.messageQueues[i] = make(chan []byte, 100) // Buffered channel
	}

	// Start server if we're the designated server (usually party 0)
	if myIndex == 0 && serverAddr != "" {
		var err error
		session.listener, err = tls.Listen("tcp", serverAddr, tlsConfig)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to start TLS listener: %v", err)
		}

		go session.acceptConnections()
	}

	// Connect to other parties
	go session.connectToParties(clientAddrs, tlsConfig)

	return session, nil
}

func (s *MTLSSession) acceptConnections() {
	defer s.listener.Close()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		// Set a deadline so we can check for cancellation
		s.listener.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second))

		conn, err := s.listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Timeout, check for cancellation and retry
			}
			fmt.Printf("Error accepting connection: %v\n", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *MTLSSession) connectToParties(clientAddrs []string, tlsConfig *tls.Config) {
	for i, addr := range clientAddrs {
		if i == s.myIndex || addr == "" {
			continue // Skip self or empty addresses
		}

		go func(partyIndex int, address string) {
			for {
				select {
				case <-s.ctx.Done():
					return
				default:
				}

				conn, err := tls.Dial("tcp", address, tlsConfig)
				if err != nil {
					time.Sleep(1 * time.Second) // Retry after delay
					continue
				}

				s.clientsMu.Lock()
				s.clients[partyIndex] = conn
				s.clientsMu.Unlock()

				go s.handleConnection(conn)
				return
			}
		}(i, addr)
	}
}

func (s *MTLSSession) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Read messages from this connection
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		// Read message length (4 bytes)
		var length uint32
		err := binary.Read(conn, binary.BigEndian, &length)
		if err != nil {
			if err != io.EOF {
				fmt.Printf("Error reading message length: %v\n", err)
			}
			return
		}

		// Read message data
		data := make([]byte, length)
		_, err = io.ReadFull(conn, data)
		if err != nil {
			fmt.Printf("Error reading message data: %v\n", err)
			return
		}

		// Extract sender from first byte (simple protocol)
		if len(data) < 1 {
			continue
		}

		sender := int(data[0])
		message := data[1:]

		// Queue the message
		if sender >= 0 && sender < s.partyCount {
			select {
			case s.messageQueues[sender] <- message:
			default:
				fmt.Printf("Warning: message queue full for party %d\n", sender)
			}
		}
	}
}

// Send implements mpc.Session interface
func (s *MTLSSession) Send(toParty int, msg []byte) error {
	if toParty < 0 || toParty >= s.partyCount || toParty == s.myIndex {
		return fmt.Errorf("invalid target party: %d", toParty)
	}

	s.clientsMu.RLock()
	conn := s.clients[toParty]
	s.clientsMu.RUnlock()

	if conn == nil {
		return fmt.Errorf("no connection to party %d", toParty)
	}

	// Prepare message with sender ID
	fullMsg := append([]byte{byte(s.myIndex)}, msg...)

	// Send length + message
	length := uint32(len(fullMsg))
	err := binary.Write(conn, binary.BigEndian, length)
	if err != nil {
		return fmt.Errorf("failed to send message length: %v", err)
	}

	_, err = conn.Write(fullMsg)
	if err != nil {
		return fmt.Errorf("failed to send message: %v", err)
	}

	return nil
}

// Receive implements mpc.Session interface
func (s *MTLSSession) Receive(fromParty int) ([]byte, error) {
	if fromParty < 0 || fromParty >= s.partyCount || fromParty == s.myIndex {
		return nil, fmt.Errorf("invalid source party: %d", fromParty)
	}

	select {
	case msg := <-s.messageQueues[fromParty]:
		return msg, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

// ReceiveAll implements mpc.Session interface
func (s *MTLSSession) ReceiveAll(fromParties []int) ([][]byte, error) {
	results := make([][]byte, len(fromParties))

	for i, party := range fromParties {
		msg, err := s.Receive(party)
		if err != nil {
			return nil, err
		}
		results[i] = msg
	}

	return results, nil
}

// MyIndex implements mpc.Session interface
func (s *MTLSSession) MyIndex() int {
	return s.myIndex
}

// PartyCount implements mpc.Session interface
func (s *MTLSSession) PartyCount() int {
	return s.partyCount
}

// Close implements mpc.Session interface
func (s *MTLSSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	s.cancel()

	if s.listener != nil {
		s.listener.Close()
	}

	s.clientsMu.Lock()
	for _, conn := range s.clients {
		if conn != nil {
			conn.Close()
		}
	}
	s.clientsMu.Unlock()

	return nil
}

// LoadTLSConfig loads TLS configuration from certificate files
func LoadTLSConfig(caCertFile, clientCertFile, clientKeyFile string, isServer bool) (*tls.Config, error) {
	// Load CA certificate
	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// Load client certificate
	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %v", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
	}

	if !isServer {
		config.ServerName = "localhost"
	}

	return config, nil
}