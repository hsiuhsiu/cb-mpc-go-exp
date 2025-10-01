package mpc

import (
	"container/list"
	"errors"
	"sync"
)

// MockSession provides an in-memory session implementation for testing
// It uses queues to simulate network communication between parties
type MockSession struct {
	myIndex int
	others  []*MockSession
	mutex   sync.Mutex
	cond    *sync.Cond
	queues  []list.List
	closed  bool
}

// NewMockSession creates a new MockSession for the specified party index
func NewMockSession(myIndex int) *MockSession {
	s := &MockSession{
		myIndex: myIndex,
		closed:  false,
	}
	s.cond = sync.NewCond(&s.mutex)
	return s
}

// setOthers configures connections to other parties
// This is called by NewMockNetwork to wire up all parties
func (s *MockSession) setOthers(sessions []*MockSession) {
	s.others = sessions
	s.queues = make([]list.List, len(sessions))
}

// Send sends a message to the specified party
func (s *MockSession) Send(toParty int, msg []byte) error {
	if toParty == s.myIndex {
		return errors.New("cannot send to self")
	}

	if toParty < 0 || toParty >= len(s.others) {
		return errors.New("invalid party index")
	}

	receiver := s.others[toParty]
	receiver.mutex.Lock()
	receiver.queues[s.myIndex].PushBack(msg)
	receiver.mutex.Unlock()
	receiver.cond.Broadcast()

	return nil
}

// Receive receives a message from the specified party (blocking)
func (s *MockSession) Receive(fromParty int) ([]byte, error) {
	if fromParty == s.myIndex {
		return nil, errors.New("cannot receive from self")
	}

	if fromParty < 0 || fromParty >= len(s.queues) {
		return nil, errors.New("invalid party index")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.closed {
		return nil, errors.New("session closed")
	}

	queue := &s.queues[fromParty]
	for queue.Len() == 0 {
		s.cond.Wait()
		if s.closed {
			return nil, errors.New("session closed")
		}
	}

	front := queue.Front()
	msg := front.Value.([]byte)
	queue.Remove(front)
	return msg, nil
}

// ReceiveAll receives messages from multiple parties concurrently
func (s *MockSession) ReceiveAll(fromParties []int) ([][]byte, error) {
	n := len(fromParties)
	messages := make([][]byte, n)
	errs := make([]error, n)

	var wg sync.WaitGroup
	wg.Add(n)

	for i, fromParty := range fromParties {
		go func(idx int, party int) {
			defer wg.Done()
			msg, err := s.Receive(party)
			messages[idx] = msg
			errs[idx] = err
		}(i, fromParty)
	}

	wg.Wait()

	// Return first error encountered
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}

	return messages, nil
}

// MyIndex returns this party's index
func (s *MockSession) MyIndex() int {
	return s.myIndex
}

// PartyCount returns the total number of parties
func (s *MockSession) PartyCount() int {
	return len(s.others)
}

// Close closes the session and unblocks any waiting receives
func (s *MockSession) Close() error {
	s.mutex.Lock()
	s.closed = true
	s.mutex.Unlock()
	s.cond.Broadcast()
	return nil
}

// NewMockNetwork creates a complete mock network with the specified number of parties
// Returns a slice of MockSession instances, one for each party, already wired together
func NewMockNetwork(nParties int) []*MockSession {
	sessions := make([]*MockSession, nParties)
	for i := 0; i < nParties; i++ {
		sessions[i] = NewMockSession(i)
	}
	for i := 0; i < nParties; i++ {
		sessions[i].setOthers(sessions)
	}
	return sessions
}
