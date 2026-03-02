package socks

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Ne0nd0g/merlin-message/jobs"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// makeJob builds a jobs.Job with a Socks payload for use in tests.
func makeJob(connID uuid.UUID, agentID uuid.UUID, index int, data []byte, close bool) jobs.Job {
	return jobs.Job{
		AgentID: agentID,
		ID:      connID.String(),
		Token:   uuid.New(),
		Type:    jobs.SOCKS,
		Payload: jobs.Socks{
			ID:    connID,
			Index: index,
			Data:  data,
			Close: close,
		},
	}
}

// socks5ConnectBytes builds a minimal SOCKS5 handshake (no-auth) followed by
// a CONNECT request to the given TCP address. Returns the full byte sequence
// that a SOCKS5 client would send.
func socks5ConnectBytes(addr string) []byte {
	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	ip := net.ParseIP(host).To4()

	var buf []byte
	// Greeting: version 5, 1 method (no-auth = 0x00)
	buf = append(buf, 0x05, 0x01, 0x00)
	// Connect request: VER CMD RSV ATYP DST.ADDR DST.PORT
	buf = append(buf, 0x05, 0x01, 0x00, 0x01)
	buf = append(buf, ip...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	buf = append(buf, portBytes...)
	return buf
}

// drainChan reads and discards jobs from ch until the returned stop function
// is called. This prevents listen() from blocking on *c.JobChan.
func drainChan(ch *chan jobs.Job) (stop func()) {
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-*ch:
			case <-done:
				return
			}
		}
	}()
	return func() { close(done) }
}

// waitForMapRemoval polls the connections sync.Map until the given key is
// removed or the timeout expires. Returns true if removed.
func waitForMapRemoval(id uuid.UUID, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, ok := connections.Load(id); !ok {
			return true
		}
		runtime.Gosched()
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// startEchoServer starts a TCP server that echoes back everything it receives.
// Returns the listener address and a function to stop the server.
func startEchoServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo server listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					continue
				}
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		close(done)
		ln.Close()
	}
}

// goroutineCount returns the current number of goroutines.
func goroutineCount() int {
	return runtime.NumGoroutine()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestSingleConnection_GarbageData(t *testing.T) {
	jobsOut := make(chan jobs.Job, 100)
	stopDrain := drainChan(&jobsOut)
	defer stopDrain()

	connID := uuid.New()
	agentID := uuid.New()

	// Send garbage (non-SOCKS5) data — ServeConn will fail immediately
	garbage := []byte("NOT_SOCKS_DATA_AT_ALL")
	job := makeJob(connID, agentID, 0, garbage, false)
	Handler(job, &jobsOut)

	// ServeConn error triggers teardown → connection should be removed from map
	if !waitForMapRemoval(connID, 5*time.Second) {
		t.Fatal("connection was not removed from map after garbage data")
	}
}

func TestConcurrentCreation(t *testing.T) {
	jobsOut := make(chan jobs.Job, 1000)
	stopDrain := drainChan(&jobsOut)
	defer stopDrain()

	agentID := uuid.New()
	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)

	ids := make([]uuid.UUID, n)
	for i := 0; i < n; i++ {
		ids[i] = uuid.New()
	}

	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			// Use nil data so ServeConn blocks waiting for SOCKS5 handshake
			// instead of immediately rejecting and tearing down
			job := makeJob(ids[idx], agentID, 0, nil, false)
			Handler(job, &jobsOut)
		}(i)
	}
	wg.Wait()

	// Small settle time for goroutines to finish Store
	time.Sleep(100 * time.Millisecond)

	// Verify all connections were created
	created := 0
	for _, id := range ids {
		if _, ok := connections.Load(id); ok {
			created++
		}
	}
	if created != n {
		t.Fatalf("expected %d connections, got %d", n, created)
	}

	// Clean up: send close for each to trigger teardown.
	// Index 0 because the initial nil-data job doesn't advance Count.
	for _, id := range ids {
		closeJob := makeJob(id, agentID, 0, nil, true)
		Handler(closeJob, &jobsOut)
	}
	// Wait for all to teardown
	for _, id := range ids {
		waitForMapRemoval(id, 5*time.Second)
	}
}

func TestSameIDConcurrentCreate(t *testing.T) {
	// Multiple goroutines call Handler with the same connection ID.
	// LoadOrStore ensures only one creates the connection; losers clean up.
	jobsOut := make(chan jobs.Job, 1000)
	stopDrain := drainChan(&jobsOut)
	defer stopDrain()

	connID := uuid.New()
	agentID := uuid.New()
	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)

	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			job := makeJob(connID, agentID, 0, nil, false)
			Handler(job, &jobsOut)
		}()
	}
	wg.Wait()

	// The key assertion: no panic, and the connection exists in the map
	if _, ok := connections.Load(connID); !ok {
		t.Fatal("connection not in map after concurrent same-ID creation")
	}

	// Teardown — index 0 because nil-data jobs don't advance Count
	closeJob := makeJob(connID, agentID, 0, nil, true)
	Handler(closeJob, &jobsOut)
	waitForMapRemoval(connID, 5*time.Second)
}

func TestRapidOpenCloseChurn(t *testing.T) {
	jobsOut := make(chan jobs.Job, 1000)
	stopDrain := drainChan(&jobsOut)
	defer stopDrain()

	agentID := uuid.New()
	baseline := goroutineCount()

	const cycles = 200
	for i := 0; i < cycles; i++ {
		connID := uuid.New()
		openJob := makeJob(connID, agentID, 0, []byte("X"), false)
		Handler(openJob, &jobsOut)

		closeJob := makeJob(connID, agentID, 1, nil, true)
		Handler(closeJob, &jobsOut)

		// Don't wait for each teardown — just fire and forget for churn pressure
	}

	// Allow goroutines to settle
	time.Sleep(3 * time.Second)

	after := goroutineCount()
	leaked := after - baseline
	// Tolerance: allow up to 5 goroutines of drift (GC, runtime, etc.)
	if leaked > 5 {
		t.Fatalf("goroutine leak: baseline=%d after=%d leaked=%d", baseline, after, leaked)
	}
}

func TestDataAndCloseRace(t *testing.T) {
	jobsOut := make(chan jobs.Job, 1000)
	stopDrain := drainChan(&jobsOut)
	defer stopDrain()

	connID := uuid.New()
	agentID := uuid.New()

	// Create connection with nil data so ServeConn blocks (connection stays alive).
	// Nil data at index 0 doesn't advance Count, so Count stays 0.
	createJob := makeJob(connID, agentID, 0, nil, false)
	Handler(createJob, &jobsOut)
	time.Sleep(50 * time.Millisecond) // Let goroutines start

	// Race: send data (index 0 matches Count=0) and close (index 1) concurrently
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		dataJob := makeJob(connID, agentID, 0, []byte("DATA"), false)
		Handler(dataJob, &jobsOut)
	}()
	go func() {
		defer wg.Done()
		closeJob := makeJob(connID, agentID, 1, nil, true)
		Handler(closeJob, &jobsOut)
	}()
	wg.Wait()

	// Assert eventual teardown: connection removed from map
	if !waitForMapRemoval(connID, 5*time.Second) {
		t.Fatal("connection not torn down after data+close race")
	}
}

func TestEnqueueDuringTeardown(t *testing.T) {
	jobsOut := make(chan jobs.Job, 1000)
	stopDrain := drainChan(&jobsOut)
	defer stopDrain()

	connID := uuid.New()
	agentID := uuid.New()

	// Create connection with nil data (Count stays 0, ServeConn blocks)
	createJob := makeJob(connID, agentID, 0, nil, false)
	Handler(createJob, &jobsOut)
	time.Sleep(100 * time.Millisecond)

	// Get the connection and trigger teardown directly.
	// This exercises the socks.go:107 race window: the done channel is closed
	// while we simultaneously try to enqueue data via Handler.
	val, ok := connections.Load(connID)
	if !ok {
		t.Fatal("connection not found in map")
	}
	c := val.(*Connection)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		c.teardown(connID) // Closes done channel, deletes from map
	}()
	go func() {
		defer wg.Done()
		// Slight delay to overlap with teardown
		time.Sleep(5 * time.Millisecond)
		// This Handler call should hit either:
		// - The done-aware select at socks.go:107-111 (data dropped)
		// - Or the "connection not found" early return at socks.go:102-104
		// Either way: no panic, no hang.
		dataJob := makeJob(connID, agentID, 0, []byte("LATE_DATA"), false)
		Handler(dataJob, &jobsOut)
	}()
	wg.Wait()

	// The key assertion: no panic, no deadlock — we reached here.
	// done channel should be closed.
	select {
	case <-c.done:
		// Good
	default:
		t.Fatal("done channel not closed after teardown")
	}
}

func TestTeardownIdempotence(t *testing.T) {
	jobsOut := make(chan jobs.Job, 100)
	stopDrain := drainChan(&jobsOut)
	defer stopDrain()

	connID := uuid.New()
	agentID := uuid.New()

	// Nil data keeps connection alive (ServeConn blocks)
	createJob := makeJob(connID, agentID, 0, nil, false)
	Handler(createJob, &jobsOut)
	time.Sleep(50 * time.Millisecond)

	// Get the connection to call teardown directly
	val, ok := connections.Load(connID)
	if !ok {
		t.Fatal("connection not found in map")
	}
	c := val.(*Connection)

	// Call teardown concurrently from multiple goroutines
	const n = 10
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			c.teardown(connID) // Should not panic due to sync.Once
		}()
	}
	wg.Wait()

	// done channel should be closed
	select {
	case <-c.done:
		// Good — closed
	default:
		t.Fatal("done channel not closed after teardown")
	}
}

func TestTeardownIsolation(t *testing.T) {
	jobsOut := make(chan jobs.Job, 1000)
	stopDrain := drainChan(&jobsOut)
	defer stopDrain()

	agentID := uuid.New()
	idA := uuid.New()
	idB := uuid.New()

	// Create two connections with nil data (both stay alive)
	Handler(makeJob(idA, agentID, 0, nil, false), &jobsOut)
	Handler(makeJob(idB, agentID, 0, nil, false), &jobsOut)
	time.Sleep(50 * time.Millisecond)

	// Teardown A (via close at index 0, Count=0 since nil data)
	Handler(makeJob(idA, agentID, 0, nil, true), &jobsOut)
	if !waitForMapRemoval(idA, 5*time.Second) {
		t.Fatal("connection A not torn down")
	}

	// B should still be functional
	valB, ok := connections.Load(idB)
	if !ok {
		t.Fatal("connection B was removed when A was torn down")
	}
	connB := valB.(*Connection)

	// B's done channel should still be open
	select {
	case <-connB.done:
		t.Fatal("connection B's done channel was closed when A was torn down")
	default:
		// Good
	}

	// Can still enqueue to B (index 0 matches Count=0)
	dataJob := makeJob(idB, agentID, 0, []byte("STILL_ALIVE"), false)
	Handler(dataJob, &jobsOut)

	// Clean up B (Count is now 1 after data was processed)
	Handler(makeJob(idB, agentID, 1, nil, true), &jobsOut)
	waitForMapRemoval(idB, 5*time.Second)
}

func TestValidSOCKS5_EndToEnd(t *testing.T) {
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()

	jobsOut := make(chan jobs.Job, 1000)
	connID := uuid.New()
	agentID := uuid.New()

	// Collect jobs from the output channel
	var received []jobs.Job
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		for {
			select {
			case j := <-jobsOut:
				mu.Lock()
				received = append(received, j)
				mu.Unlock()
			case <-done:
				return
			}
		}
	}()

	// Send SOCKS5 handshake as first message
	handshake := socks5ConnectBytes(echoAddr)
	createJob := makeJob(connID, agentID, 0, handshake, false)
	Handler(createJob, &jobsOut)

	// Wait for the SOCKS5 response (auth reply + connect reply come through jobsOut)
	time.Sleep(500 * time.Millisecond)

	// Send actual data through the tunnel
	testData := []byte("ECHO_TEST_PAYLOAD")
	dataJob := makeJob(connID, agentID, 1, testData, false)
	Handler(dataJob, &jobsOut)

	// Wait for echo response to come back through listen()
	time.Sleep(1 * time.Second)

	// Close the connection
	closeJob := makeJob(connID, agentID, 2, nil, true)
	Handler(closeJob, &jobsOut)

	// Wait for teardown
	waitForMapRemoval(connID, 5*time.Second)
	close(done)

	// Verify we got some output jobs (SOCKS5 handshake responses + echoed data)
	mu.Lock()
	defer mu.Unlock()
	if len(received) == 0 {
		t.Fatal("no jobs received from SOCKS5 end-to-end test")
	}

	// Check that our test data appears somewhere in the response payloads
	found := false
	for _, j := range received {
		s, ok := j.Payload.(jobs.Socks)
		if !ok {
			continue
		}
		for i := range s.Data {
			if len(s.Data[i:]) >= len(testData) {
				if string(s.Data[i:i+len(testData)]) == string(testData) {
					found = true
					break
				}
			}
		}
		if found {
			break
		}
	}
	if !found {
		t.Log("received jobs payloads:")
		for i, j := range received {
			if s, ok := j.Payload.(jobs.Socks); ok {
				t.Logf("  [%d] index=%d len=%d data=%q", i, s.Index, len(s.Data), s.Data)
			}
		}
		t.Fatal("echoed test data not found in output jobs")
	}
}

func TestOutOfOrderPackets(t *testing.T) {
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()

	jobsOut := make(chan jobs.Job, 1000)
	connID := uuid.New()
	agentID := uuid.New()

	// Collect output
	var received []jobs.Job
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		for {
			select {
			case j := <-jobsOut:
				mu.Lock()
				received = append(received, j)
				mu.Unlock()
			case <-done:
				return
			}
		}
	}()

	// Send SOCKS5 handshake (index 0)
	handshake := socks5ConnectBytes(echoAddr)
	Handler(makeJob(connID, agentID, 0, handshake, false), &jobsOut)
	time.Sleep(500 * time.Millisecond)

	// Send index 2 BEFORE index 1 — tests resequencing in send()
	Handler(makeJob(connID, agentID, 2, []byte("WORLD"), false), &jobsOut)
	time.Sleep(50 * time.Millisecond)
	Handler(makeJob(connID, agentID, 1, []byte("HELLO"), false), &jobsOut)

	// Wait for both to be processed and echoed back
	time.Sleep(2 * time.Second)

	// Close
	Handler(makeJob(connID, agentID, 3, nil, true), &jobsOut)
	waitForMapRemoval(connID, 5*time.Second)
	close(done)

	// Verify both strings appear in output
	mu.Lock()
	defer mu.Unlock()

	allData := []byte{}
	for _, j := range received {
		if s, ok := j.Payload.(jobs.Socks); ok {
			allData = append(allData, s.Data...)
		}
	}

	dataStr := string(allData)
	if !contains(dataStr, "HELLO") || !contains(dataStr, "WORLD") {
		t.Fatalf("expected both HELLO and WORLD in echoed data, got: %q", dataStr)
	}
}

func TestManyConnectionsParallelDataFlow(t *testing.T) {
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()

	jobsOut := make(chan jobs.Job, 10000)

	// Collect output keyed by connection ID
	outputByConn := sync.Map{}
	done := make(chan struct{})
	var drainWg sync.WaitGroup
	drainWg.Add(1)
	go func() {
		defer drainWg.Done()
		for {
			select {
			case j := <-jobsOut:
				if s, ok := j.Payload.(jobs.Socks); ok {
					val, _ := outputByConn.LoadOrStore(s.ID, &[]byte{})
					buf := val.(*[]byte)
					*buf = append(*buf, s.Data...)
				}
			case <-done:
				return
			}
		}
	}()

	agentID := uuid.New()
	const n = 20
	handshake := socks5ConnectBytes(echoAddr)

	type connInfo struct {
		id     uuid.UUID
		marker string
	}
	conns := make([]connInfo, n)

	// Create all connections
	for i := 0; i < n; i++ {
		conns[i] = connInfo{
			id:     uuid.New(),
			marker: fmt.Sprintf("MARKER_%03d", i),
		}
		Handler(makeJob(conns[i].id, agentID, 0, handshake, false), &jobsOut)
	}
	time.Sleep(500 * time.Millisecond)

	// Send unique markers through each connection
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			ci := conns[idx]
			Handler(makeJob(ci.id, agentID, 1, []byte(ci.marker), false), &jobsOut)
		}(i)
	}
	wg.Wait()

	// Wait for echoes
	time.Sleep(2 * time.Second)

	// Close all connections
	for i := 0; i < n; i++ {
		Handler(makeJob(conns[i].id, agentID, 2, nil, true), &jobsOut)
	}
	for i := 0; i < n; i++ {
		waitForMapRemoval(conns[i].id, 5*time.Second)
	}
	close(done)
	drainWg.Wait() // Ensure drain goroutine has fully exited before reading

	// Verify no cross-contamination: each connection's output should contain
	// only its own marker, not another connection's marker
	var errCount atomic.Int32
	for i := 0; i < n; i++ {
		ci := conns[i]
		val, ok := outputByConn.Load(ci.id)
		if !ok {
			t.Errorf("no output for connection %d (%s)", i, ci.id)
			errCount.Add(1)
			continue
		}
		data := string(*val.(*[]byte))

		if !contains(data, ci.marker) {
			t.Errorf("connection %d: marker %q not found in output", i, ci.marker)
			errCount.Add(1)
			continue
		}

		// Check no other connection's marker leaked in
		for j := 0; j < n; j++ {
			if j == i {
				continue
			}
			if contains(data, conns[j].marker) {
				t.Errorf("cross-talk: connection %d output contains connection %d marker %q", i, j, conns[j].marker)
				errCount.Add(1)
			}
		}
	}

	if errCount.Load() > 0 {
		t.Fatalf("%d cross-contamination errors detected", errCount.Load())
	}
}

func TestOrphanPrevention(t *testing.T) {
	jobsOut := make(chan jobs.Job, 100)
	stopDrain := drainChan(&jobsOut)
	defer stopDrain()

	connID := uuid.New()
	agentID := uuid.New()

	// Create and immediately tear down a connection
	garbage := []byte("NOT_SOCKS")
	Handler(makeJob(connID, agentID, 0, garbage, false), &jobsOut)
	if !waitForMapRemoval(connID, 5*time.Second) {
		t.Fatal("connection not torn down after garbage data")
	}

	// Verify the ID is tombstoned
	if _, ok := tombstones.Load(connID); !ok {
		t.Fatal("connection ID not tombstoned after teardown")
	}

	baseline := goroutineCount()

	// Late Handler call with Close=false on the same ID — should be rejected
	lateJob := makeJob(connID, agentID, 1, []byte("LATE_DATA"), false)
	Handler(lateJob, &jobsOut)

	// Connection must NOT be recreated
	if _, ok := connections.Load(connID); ok {
		t.Fatal("orphan connection was recreated despite tombstone")
	}

	// No goroutine leak
	time.Sleep(200 * time.Millisecond)
	after := goroutineCount()
	if after-baseline > 2 {
		t.Fatalf("goroutine leak after orphan prevention: baseline=%d after=%d", baseline, after)
	}
}

func TestListenExitsOnTeardown(t *testing.T) {
	jobsOut := make(chan jobs.Job, 100) // intentionally small — will fill up
	connID := uuid.New()
	agentID := uuid.New()

	// Create connection with nil data (ServeConn blocks)
	Handler(makeJob(connID, agentID, 0, nil, false), &jobsOut)
	time.Sleep(100 * time.Millisecond)

	// Fill the output channel to capacity so listen() blocks on send
	for i := 0; i < cap(jobsOut); i++ {
		jobsOut <- jobs.Job{}
	}

	baseline := goroutineCount()

	// Trigger teardown — listen() should unblock via done channel
	val, ok := connections.Load(connID)
	if !ok {
		t.Fatal("connection not found")
	}
	val.(*Connection).teardown(connID)

	// Wait for goroutines to exit
	time.Sleep(500 * time.Millisecond)

	after := goroutineCount()
	// At least 2 goroutines should have exited (listen + send; start may also exit)
	if after > baseline {
		t.Fatalf("goroutine leak after teardown with full channel: baseline=%d after=%d", baseline, after)
	}
}

func TestResequencingUnderLoad(t *testing.T) {
	echoAddr, stopEcho := startEchoServer(t)
	defer stopEcho()

	jobsOut := make(chan jobs.Job, 10000)
	connID := uuid.New()
	agentID := uuid.New()

	// Collect output
	var received []jobs.Job
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		for {
			select {
			case j := <-jobsOut:
				mu.Lock()
				received = append(received, j)
				mu.Unlock()
			case <-done:
				return
			}
		}
	}()

	// SOCKS5 handshake (index 0)
	handshake := socks5ConnectBytes(echoAddr)
	Handler(makeJob(connID, agentID, 0, handshake, false), &jobsOut)
	time.Sleep(500 * time.Millisecond)

	// Send 50 jobs with fully reversed indices: [50, 49, ..., 2, 1]
	const n = 50
	for i := n; i >= 1; i-- {
		data := []byte(fmt.Sprintf("PKT%03d|", i))
		Handler(makeJob(connID, agentID, i, data, false), &jobsOut)
	}

	// Wait for all resequencing and echo
	time.Sleep(5 * time.Second)

	// Close (index n+1 = 51)
	Handler(makeJob(connID, agentID, n+1, nil, true), &jobsOut)
	waitForMapRemoval(connID, 5*time.Second)
	close(done)

	// Verify all data arrived in correct order
	mu.Lock()
	defer mu.Unlock()

	var allData []byte
	for _, j := range received {
		if s, ok := j.Payload.(jobs.Socks); ok {
			allData = append(allData, s.Data...)
		}
	}

	dataStr := string(allData)
	// Verify each packet marker is present
	for i := 1; i <= n; i++ {
		marker := fmt.Sprintf("PKT%03d|", i)
		if !contains(dataStr, marker) {
			t.Fatalf("missing packet %d (marker %q) in echoed data", i, marker)
		}
	}

	// Verify correct ordering: PKT001 should appear before PKT002, etc.
	lastIdx := 0
	for i := 1; i <= n; i++ {
		marker := fmt.Sprintf("PKT%03d|", i)
		idx := searchIndex(dataStr, marker)
		if idx < lastIdx {
			t.Fatalf("out-of-order: PKT%03d at index %d but previous packet ended at %d", i, idx, lastIdx)
		}
		lastIdx = idx + len(marker)
	}
}

// searchIndex returns the index of the first occurrence of substr in s, or -1.
func searchIndex(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// contains checks if s contains substr.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
