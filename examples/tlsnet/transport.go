package tlsnet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"time"

	"github.com/coinbase/cb-mpc-go/pkg/cbmpc"
)

// Config configures the TLS-backed transport between parties.
type Config struct {
	Self        int
	Names       []string
	Addresses   []string
	Certificate tls.Certificate
	RootCAs     *x509.CertPool
}

// Transport implements cbmpc.Transport using long-lived mTLS connections between parties.
type Transport struct {
	self  cbmpc.RoleID
	names []string

	ctx    context.Context
	cancel context.CancelFunc

	mu    sync.RWMutex
	peers map[cbmpc.RoleID]*peerConn

	listener  net.Listener
	closeOnce sync.Once
}

type peerConn struct {
	id   cbmpc.RoleID
	conn net.Conn

	send chan []byte
	recv chan []byte

	errOnce       sync.Once
	err           error
	closeRecvOnce sync.Once
}

// New establishes mTLS connections with every other party and returns a ready-to-use transport.
func New(cfg Config) (*Transport, error) {
	if cfg.RootCAs == nil {
		return nil, errors.New("tlsnet: root CA pool required")
	}
	if cfg.Self < 0 || cfg.Self >= len(cfg.Names) {
		return nil, fmt.Errorf("tlsnet: invalid self index %d", cfg.Self)
	}
	if len(cfg.Names) != len(cfg.Addresses) {
		return nil, errors.New("tlsnet: names/addresses length mismatch")
	}
	if len(cfg.Names) < 2 {
		return nil, errors.New("tlsnet: at least two parties required")
	}
	if len(cfg.Names) > math.MaxUint32 {
		return nil, fmt.Errorf("tlsnet: too many parties (%d) for 32-bit role IDs", len(cfg.Names))
	}

	selfRole, err := roleIDFromIndex(cfg.Self)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	t := &Transport{
		self:   selfRole,
		names:  append([]string(nil), cfg.Names...),
		ctx:    ctx,
		cancel: cancel,
		peers:  make(map[cbmpc.RoleID]*peerConn),
	}

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{cfg.Certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    cfg.RootCAs,
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", cfg.Addresses[cfg.Self], serverTLS)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("tlsnet: listen: %w", err)
	}
	t.listener = ln

	expectedPeers := len(cfg.Names) - 1
	var ready sync.WaitGroup
	ready.Add(expectedPeers)
	errCh := make(chan error, expectedPeers)

	register := func(id cbmpc.RoleID, conn *tls.Conn) error {
		t.mu.Lock()
		if _, exists := t.peers[id]; exists {
			t.mu.Unlock()
			return fmt.Errorf("tlsnet: duplicate connection from peer %d", id)
		}
		pc := newPeerConn(t.ctx, id, conn)
		t.peers[id] = pc
		t.mu.Unlock()
		ready.Done()
		return nil
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-t.ctx.Done():
					return
				default:
					errCh <- fmt.Errorf("tlsnet: accept: %w", err)
					return
				}
			}
			tlsConn, ok := conn.(*tls.Conn)
			if !ok {
				errCh <- closeWithContextErr(conn, errors.New("tlsnet: non-TLS connection accepted"))
				return
			}
			if err := tlsConn.Handshake(); err != nil {
				errCh <- closeWithContextErr(tlsConn, fmt.Errorf("tlsnet: handshake: %w", err))
				return
			}
			peerID, err := readPeerID(tlsConn)
			if err != nil {
				errCh <- closeWithContextErr(tlsConn, fmt.Errorf("tlsnet: read peer id: %w", err))
				return
			}
			if uint64(peerID) >= uint64(len(cfg.Names)) {
				errCh <- closeWithContextErr(tlsConn, fmt.Errorf("tlsnet: unexpected peer id %d", peerID))
				return
			}
			if err := register(cbmpc.RoleID(peerID), tlsConn); err != nil {
				errCh <- closeWithContextErr(tlsConn, err)
				return
			}
		}
	}()

	clientTLSBase := &tls.Config{
		Certificates: []tls.Certificate{cfg.Certificate},
		RootCAs:      cfg.RootCAs,
		MinVersion:   tls.VersionTLS12,
	}

	for peer := range cfg.Names {
		if peer == cfg.Self {
			continue
		}
		if peer < cfg.Self {
			continue // lower-index peers will dial us
		}
		peerIdx := peer
		go func() {
			addr := cfg.Addresses[peerIdx]
			tlsCfg := clientTLSBase.Clone()
			tlsCfg.ServerName = cfg.Names[peerIdx]
			for {
				select {
				case <-t.ctx.Done():
					return
				default:
				}
				conn, err := tls.Dial("tcp", addr, tlsCfg)
				if err != nil {
					time.Sleep(200 * time.Millisecond)
					continue
				}
				if err := writePeerID(conn, uint32(selfRole)); err != nil {
					if closeErr := conn.Close(); closeErr != nil {
						errCh <- fmt.Errorf("tlsnet: close after write peer id: %w", closeErr)
					}
					time.Sleep(200 * time.Millisecond)
					continue
				}
				roleID, err := roleIDFromIndex(peerIdx)
				if err != nil {
					errCh <- closeWithContextErr(conn, err)
					return
				}
				if err := register(roleID, conn); err != nil {
					errCh <- closeWithContextErr(conn, err)
					return
				}
				return
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		ready.Wait()
		close(done)
	}()

	select {
	case <-done:
		return t, nil
	case err := <-errCh:
		cancel()
		return nil, err
	case <-time.After(10 * time.Second):
		cancel()
		return nil, errors.New("tlsnet: timeout waiting for peer connections")
	}
}

func (t *Transport) Send(ctx context.Context, to cbmpc.RoleID, msg []byte) error {
	if to == t.self {
		return errors.New("tlsnet: send to self")
	}
	pc, err := t.getPeer(to)
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.ctx.Done():
		return errors.New("tlsnet: transport closed")
	case pc.send <- append([]byte(nil), msg...):
		return nil
	}
}

func (t *Transport) Receive(ctx context.Context, from cbmpc.RoleID) ([]byte, error) {
	if from == t.self {
		return nil, errors.New("tlsnet: receive from self")
	}
	pc, err := t.getPeer(from)
	if err != nil {
		return nil, err
	}
	return pc.recvOne(ctx, t.ctx)
}

func (t *Transport) ReceiveAll(ctx context.Context, from []cbmpc.RoleID) (map[cbmpc.RoleID][]byte, error) {
	uniq := make(map[cbmpc.RoleID]struct{}, len(from))
	for _, role := range from {
		if role == t.self {
			return nil, errors.New("tlsnet: receive_all includes self")
		}
		if _, err := t.getPeer(role); err != nil {
			return nil, err
		}
		if _, exists := uniq[role]; exists {
			return nil, errors.New("tlsnet: duplicate role in receive_all")
		}
		uniq[role] = struct{}{}
	}

	out := make(map[cbmpc.RoleID][]byte, len(from))
	for _, role := range from {
		pc, _ := t.getPeer(role)
		msg, err := pc.recvOne(ctx, t.ctx)
		if err != nil {
			return nil, err
		}
		out[role] = msg
	}
	return out, nil
}

// Close terminates the transport and underlying connections.
func (t *Transport) Close() error {
	t.closeOnce.Do(func() {
		t.cancel()
		if t.listener != nil {
			_ = t.listener.Close()
		}
		t.mu.Lock()
		for _, pc := range t.peers {
			pc.close()
		}
		t.mu.Unlock()
	})
	return nil
}

func (t *Transport) getPeer(id cbmpc.RoleID) (*peerConn, error) {
	t.mu.RLock()
	pc, ok := t.peers[id]
	t.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("tlsnet: unknown peer %d", id)
	}
	return pc, nil
}

func newPeerConn(ctx context.Context, id cbmpc.RoleID, conn net.Conn) *peerConn {
	pc := &peerConn{
		id:   id,
		conn: conn,
		send: make(chan []byte, 16),
		recv: make(chan []byte, 16),
	}
	go pc.writer(ctx)
	go pc.reader(ctx)
	return pc
}

func (pc *peerConn) writer(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			pc.setErr(ctx.Err())
			return
		case msg, ok := <-pc.send:
			if !ok {
				return
			}
			if err := writeFrame(pc.conn, msg); err != nil {
				pc.setErr(err)
				return
			}
		}
	}
}

func (pc *peerConn) reader(ctx context.Context) {
	for {
		msg, err := readFrame(pc.conn)
		if err != nil {
			pc.setErr(err)
			pc.closeRecv()
			return
		}
		select {
		case pc.recv <- msg:
		case <-ctx.Done():
			pc.setErr(ctx.Err())
			pc.closeRecv()
			return
		}
	}
}

func (pc *peerConn) recvOne(ctx, transportCtx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-transportCtx.Done():
		return nil, errors.New("tlsnet: transport closed")
	case msg, ok := <-pc.recv:
		if !ok {
			return nil, pc.errOr(io.EOF)
		}
		return msg, nil
	}
}

func (pc *peerConn) close() {
	pc.setErr(io.EOF)
	pc.closeRecv()
}

func (pc *peerConn) setErr(err error) {
	pc.errOnce.Do(func() {
		if err == nil {
			err = io.EOF
		}
		pc.err = err
		_ = pc.conn.Close()
		close(pc.send)
	})
}

func (pc *peerConn) closeRecv() {
	pc.closeRecvOnce.Do(func() {
		close(pc.recv)
	})
}

func (pc *peerConn) errOr(fallback error) error {
	if pc.err != nil {
		return pc.err
	}
	return fallback
}

func writeFrame(conn net.Conn, payload []byte) error {
	size := len(payload)
	if size < 0 || size > math.MaxUint32 {
		return fmt.Errorf("tlsnet: frame too large (%d bytes)", size)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(size))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	return nil
}

func readFrame(conn net.Conn) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writePeerID(conn net.Conn, id uint32) error {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], id)
	_, err := conn.Write(buf[:])
	return err
}

func readPeerID(conn net.Conn) (uint32, error) {
	var buf [4]byte
	if _, err := io.ReadFull(conn, buf[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(buf[:]), nil
}

func roleIDFromIndex(idx int) (cbmpc.RoleID, error) {
	if idx < 0 {
		return 0, fmt.Errorf("tlsnet: negative role index %d", idx)
	}
	if idx > math.MaxUint32 {
		return 0, fmt.Errorf("tlsnet: role index %d exceeds 32-bit capacity", idx)
	}
	return cbmpc.RoleID(idx), nil
}

func closeWithContextErr(c io.Closer, base error) error {
	if base == nil {
		return c.Close()
	}
	if closeErr := c.Close(); closeErr != nil {
		return fmt.Errorf("%w; close error: %v", base, closeErr)
	}
	return base
}
