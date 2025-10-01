package mpc

import (
	"errors"
	"sync"
)

// MaliciousSession wraps a normal session with malicious behavior for testing
// This is used to test protocol robustness against adversarial parties
type MaliciousSession struct {
	inner    Session
	behavior MaliciousBehavior
	mutex    sync.Mutex

	// State tracking
	sendCount    int
	receiveCount int
}

// MaliciousBehavior defines what kind of malicious action to perform
type MaliciousBehavior struct {
	// DropAllSends - drop all outgoing messages (simulate network partition)
	DropAllSends bool

	// DropAllReceives - fail all receive operations
	DropAllReceives bool

	// CorruptMessages - modify message contents before sending
	CorruptMessages bool

	// SendWrongSize - send messages with incorrect size
	SendWrongSize bool

	// FailAfterNSends - fail after N send operations
	FailAfterNSends int

	// FailAfterNReceives - fail after N receive operations
	FailAfterNReceives int

	// SendEmptyMessages - send empty messages instead of real data
	SendEmptyMessages bool

	// SendGarbage - send random garbage instead of protocol messages
	SendGarbage bool

	// ReplayFirstMessage - replay the first sent message repeatedly
	ReplayFirstMessage bool
	firstMessage       []byte

	// FlipRandomBits - flip random bits in messages
	FlipRandomBits bool
}

// NewMaliciousSession wraps a session with malicious behavior
func NewMaliciousSession(inner Session, behavior MaliciousBehavior) *MaliciousSession {
	return &MaliciousSession{
		inner:    inner,
		behavior: behavior,
	}
}

// Send implements Session.Send with malicious behavior
func (m *MaliciousSession) Send(toParty int, msg []byte) error {
	m.mutex.Lock()
	m.sendCount++
	count := m.sendCount
	m.mutex.Unlock()

	// Check if we should fail after N sends
	if m.behavior.FailAfterNSends > 0 && count > m.behavior.FailAfterNSends {
		return errors.New("malicious: failing after N sends")
	}

	// Drop all sends
	if m.behavior.DropAllSends {
		// Pretend success but don't actually send
		return nil
	}

	// Send empty messages
	if m.behavior.SendEmptyMessages {
		return m.inner.Send(toParty, []byte{})
	}

	// Send garbage
	if m.behavior.SendGarbage {
		garbage := make([]byte, len(msg))
		for i := range garbage {
			garbage[i] = 0xFF // All 1s
		}
		return m.inner.Send(toParty, garbage)
	}

	// Replay first message
	if m.behavior.ReplayFirstMessage {
		if m.behavior.firstMessage == nil {
			m.behavior.firstMessage = make([]byte, len(msg))
			copy(m.behavior.firstMessage, msg)
		}
		return m.inner.Send(toParty, m.behavior.firstMessage)
	}

	// Corrupt messages
	if m.behavior.CorruptMessages {
		corrupted := make([]byte, len(msg))
		copy(corrupted, msg)
		// Flip all bits in first byte
		if len(corrupted) > 0 {
			corrupted[0] ^= 0xFF
		}
		return m.inner.Send(toParty, corrupted)
	}

	// Send wrong size
	if m.behavior.SendWrongSize {
		if len(msg) > 0 {
			// Send only half the message
			return m.inner.Send(toParty, msg[:len(msg)/2])
		}
	}

	// Flip random bits
	if m.behavior.FlipRandomBits {
		corrupted := make([]byte, len(msg))
		copy(corrupted, msg)
		// Flip bits in the middle of the message
		if len(corrupted) > 4 {
			corrupted[len(corrupted)/2] ^= 0x01
		}
		return m.inner.Send(toParty, corrupted)
	}

	// Normal send
	return m.inner.Send(toParty, msg)
}

// Receive implements Session.Receive with malicious behavior
func (m *MaliciousSession) Receive(fromParty int) ([]byte, error) {
	m.mutex.Lock()
	m.receiveCount++
	count := m.receiveCount
	m.mutex.Unlock()

	// Check if we should fail after N receives
	if m.behavior.FailAfterNReceives > 0 && count > m.behavior.FailAfterNReceives {
		return nil, errors.New("malicious: failing after N receives")
	}

	// Drop all receives
	if m.behavior.DropAllReceives {
		return nil, errors.New("malicious: dropping all receives")
	}

	// Normal receive
	return m.inner.Receive(fromParty)
}

// ReceiveAll implements Session.ReceiveAll with malicious behavior
func (m *MaliciousSession) ReceiveAll(fromParties []int) ([][]byte, error) {
	m.mutex.Lock()
	m.receiveCount += len(fromParties)
	count := m.receiveCount
	m.mutex.Unlock()

	// Check if we should fail after N receives
	if m.behavior.FailAfterNReceives > 0 && count > m.behavior.FailAfterNReceives {
		return nil, errors.New("malicious: failing after N receives")
	}

	// Drop all receives
	if m.behavior.DropAllReceives {
		return nil, errors.New("malicious: dropping all receives")
	}

	// Normal receive
	return m.inner.ReceiveAll(fromParties)
}

// MyIndex implements Session.MyIndex
func (m *MaliciousSession) MyIndex() int {
	return m.inner.MyIndex()
}

// PartyCount implements Session.PartyCount
func (m *MaliciousSession) PartyCount() int {
	return m.inner.PartyCount()
}

// Close implements Session.Close
func (m *MaliciousSession) Close() error {
	return m.inner.Close()
}

// NewMaliciousNetwork creates a mock network where one party is malicious
func NewMaliciousNetwork(nParties int, maliciousParty int, behavior MaliciousBehavior) []Session {
	// Create normal mock network
	mockSessions := NewMockNetwork(nParties)

	// Wrap sessions - make one malicious
	sessions := make([]Session, nParties)
	for i := 0; i < nParties; i++ {
		if i == maliciousParty {
			sessions[i] = NewMaliciousSession(mockSessions[i], behavior)
		} else {
			sessions[i] = mockSessions[i]
		}
	}

	return sessions
}
