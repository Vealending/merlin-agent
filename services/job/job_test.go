package job

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Ne0nd0g/merlin-message/jobs"
)

// makeResultJob creates a simple RESULT job for testing.
func makeResultJob() jobs.Job {
	return jobs.Job{
		AgentID: uuid.New(),
		ID:      uuid.New().String(),
		Token:   uuid.New(),
		Type:    jobs.RESULT,
		Payload: jobs.Results{
			Stdout: "test",
		},
	}
}

// dummyService returns a Service suitable for calling Check() and Get().
// It does not initialize the memoryService singleton (avoids agent/client deps).
func dummyService() *Service {
	return &Service{
		Agent: uuid.New(),
	}
}

func TestCheck_Concurrent_NoRace(t *testing.T) {
	svc := dummyService()

	// 1 producer pushing 1000 jobs
	const totalJobs = 1000
	go func() {
		for i := 0; i < totalJobs; i++ {
			out <- makeResultJob()
		}
	}()

	// 10 concurrent consumers calling Check()
	const consumers = 10
	var collected atomic.Int64
	var wg sync.WaitGroup
	wg.Add(consumers)

	for c := 0; c < consumers; c++ {
		go func() {
			defer wg.Done()
			deadline := time.After(5 * time.Second)
			for {
				select {
				case <-deadline:
					return
				default:
					got := svc.Check()
					collected.Add(int64(len(got)))
					if collected.Load() >= totalJobs {
						return
					}
					// Small yield to avoid busy-spin
					time.Sleep(time.Millisecond)
				}
			}
		}()
	}
	wg.Wait()

	got := collected.Load()
	if got < totalJobs {
		t.Fatalf("expected at least %d jobs collected, got %d", totalJobs, got)
	}
}

func TestGet_BlocksUntilAvailable(t *testing.T) {
	svc := dummyService()

	done := make(chan struct{})
	var result []jobs.Job

	go func() {
		result = svc.Get() // Should block
		close(done)
	}()

	// Verify it's still blocking after 200ms
	select {
	case <-done:
		t.Fatal("Get() returned before any job was available")
	case <-time.After(200 * time.Millisecond):
		// Good, still blocking
	}

	// Now send a job
	out <- makeResultJob()

	// Get() should unblock
	select {
	case <-done:
		if len(result) != 1 {
			t.Fatalf("expected 1 job, got %d", len(result))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Get() did not unblock after job was sent")
	}
}

func TestGet_BatchDrain(t *testing.T) {
	svc := dummyService()

	// Pre-fill 60 jobs
	for i := 0; i < 60; i++ {
		out <- makeResultJob()
	}
	// Let the channel buffer settle
	time.Sleep(50 * time.Millisecond)

	result := svc.Get()

	// maxBatch is 50, so Get() should return at most 50
	if len(result) > 50 {
		t.Fatalf("expected <= 50 jobs, got %d", len(result))
	}
	if len(result) == 0 {
		t.Fatal("expected at least 1 job, got 0")
	}

	// Drain remaining
	remaining := svc.Check()
	total := len(result) + len(remaining)
	if total != 60 {
		t.Fatalf("expected 60 total jobs, got %d (Get=%d, Check=%d)", total, len(result), len(remaining))
	}
}

func TestCheck_Empty_ReturnsImmediately(t *testing.T) {
	svc := dummyService()

	// Drain any leftover jobs from other tests
	for {
		got := svc.Check()
		if len(got) == 0 {
			break
		}
	}

	start := time.Now()
	result := svc.Check()
	elapsed := time.Since(start)

	if len(result) != 0 {
		t.Fatalf("expected empty slice, got %d jobs", len(result))
	}
	// Check() should return nearly instantly (< 50ms)
	if elapsed > 50*time.Millisecond {
		t.Fatalf("Check() took too long: %v", elapsed)
	}
}

func TestGet_ConcurrentProducersConsumers(t *testing.T) {
	svc := dummyService()

	const producers = 5
	const jobsPerProducer = 200
	const totalJobs = producers * jobsPerProducer
	const consumers = 3
	const sentinelID = "SENTINEL"

	// Start consumers first — they call Get() which blocks until jobs arrive
	var mu sync.Mutex
	var receivedIDs []string
	var totalReceived atomic.Int64
	var consWg sync.WaitGroup
	consWg.Add(consumers)

	for c := 0; c < consumers; c++ {
		go func() {
			defer consWg.Done()
			for {
				got := svc.Get()
				for _, j := range got {
					if j.ID == sentinelID {
						return
					}
					mu.Lock()
					receivedIDs = append(receivedIDs, j.ID)
					mu.Unlock()
					totalReceived.Add(1)
				}
			}
		}()
	}

	// Start producers
	var prodWg sync.WaitGroup
	prodWg.Add(producers)
	for p := 0; p < producers; p++ {
		go func() {
			defer prodWg.Done()
			for j := 0; j < jobsPerProducer; j++ {
				out <- makeResultJob()
			}
		}()
	}

	// Wait for producers to finish
	prodWg.Wait()

	// Wait for all jobs to be consumed
	deadline := time.After(15 * time.Second)
	for totalReceived.Load() < totalJobs {
		select {
		case <-deadline:
			t.Fatalf("consumers timed out: received %d of %d", totalReceived.Load(), totalJobs)
		case <-time.After(50 * time.Millisecond):
		}
	}

	// Send sentinel jobs to unblock consumers stuck in Get()
	for c := 0; c < consumers; c++ {
		out <- jobs.Job{ID: sentinelID}
	}
	consWg.Wait()

	// Verify no duplicates
	mu.Lock()
	defer mu.Unlock()

	seen := make(map[string]int)
	for _, id := range receivedIDs {
		seen[id]++
	}

	dupes := 0
	for _, count := range seen {
		if count > 1 {
			dupes++
		}
	}

	if len(receivedIDs) != totalJobs {
		t.Fatalf("expected %d jobs received, got %d", totalJobs, len(receivedIDs))
	}
	if dupes > 0 {
		t.Fatalf("found %d duplicate job IDs", dupes)
	}
}

func TestCheck_And_Get_Interleaved(t *testing.T) {
	svc := dummyService()

	const totalJobs = 100
	var totalReceived atomic.Int64
	done := make(chan struct{})

	// Producer: steadily feed jobs
	go func() {
		for i := 0; i < totalJobs; i++ {
			out <- makeResultJob()
			time.Sleep(time.Millisecond)
		}
	}()

	// Consumer 1: uses Check() in a polling loop
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				got := svc.Check()
				totalReceived.Add(int64(len(got)))
				time.Sleep(5 * time.Millisecond)
			}
		}
	}()

	// Consumer 2: reads directly from out channel with timeout
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			case j := <-out:
				totalReceived.Add(1)
				_ = j
			case <-time.After(200 * time.Millisecond):
				// Yield — no jobs available right now
			}
		}
	}()

	// Wait until all jobs consumed
	deadline := time.After(10 * time.Second)
	for totalReceived.Load() < totalJobs {
		select {
		case <-deadline:
			close(done)
			wg.Wait()
			t.Fatalf("interleaved test timed out: received %d of %d", totalReceived.Load(), totalJobs)
		case <-time.After(50 * time.Millisecond):
		}
	}

	close(done)
	wg.Wait()

	got := totalReceived.Load()
	if got < int64(totalJobs) {
		t.Fatalf("expected %d jobs, got %d", totalJobs, got)
	}
}
