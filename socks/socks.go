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

// Package socks handles SOCKS5 messages from the server
package socks

import (
	// Standard
	"fmt"
	"net"
	"runtime"
	"sync"

	// 3rd Party
	"github.com/armon/go-socks5"
	"github.com/google/uuid"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/v2/cli"
	"github.com/Ne0nd0g/merlin-message/jobs"
)

var server *socks5.Server
var connections = sync.Map{}

// Connection is a structure used to track new SOCKS client connections
type Connection struct {
	Job       jobs.Job
	In        net.Conn
	Out       net.Conn
	JobChan   *chan jobs.Job   // Channel to send jobs back to the server
	in        *chan jobs.Socks // Channel to receive and process SOCKS data locally
	Count     int              // Counter to track the number of SOCKS messages sent
	done      chan struct{}     // Closed on teardown to signal all goroutines to exit
	closeOnce sync.Once        // Ensures teardown runs exactly once
}

// teardown cleanly shuts down the connection: closes pipes, removes from map, signals goroutines
func (c *Connection) teardown(id uuid.UUID) {
	c.closeOnce.Do(func() {
		cli.Message(cli.NOTE, fmt.Sprintf("Tearing down SOCKS connection %s", id))
		c.Out.Close()
		c.In.Close()
		connections.Delete(id)
		close(c.done)
	})
}

// Handler is the entry point for SOCKS connections.
// This function starts a SOCKS server and processes incoming SOCKS connections
func Handler(msg jobs.Job, jobsOut *chan jobs.Job) {
	job := msg.Payload.(jobs.Socks)

	// See if the SOCKS server has already been created
	if server == nil {
		err := newSOCKSServer()
		if err != nil {
			cli.Message(cli.WARN, err.Error())
			return
		}
	}

	// See if this connection is new
	_, ok := connections.Load(job.ID)
	if !ok && !job.Close {
		client, target := net.Pipe()
		in := make(chan jobs.Socks, 100)
		connection := Connection{
			Job:     msg,
			In:      client,
			Out:     target,
			JobChan: jobsOut,
			in:      &in,
			done:    make(chan struct{}),
		}
		connections.Store(job.ID, &connection)

		// Start the go routines to serve the SOCKS connection
		go start(job.ID)
		go listen(job.ID)
		go send(job.ID)
	}

	conn, ok := connections.Load(job.ID)
	if !ok {
		cli.Message(cli.WARN, fmt.Sprintf("connection ID %s was not found", job.ID))
		return
	}
	// Done-aware enqueue: don't block if connection is being torn down
	select {
	case *conn.(*Connection).in <- job:
	case <-conn.(*Connection).done:
		cli.Message(cli.DEBUG, fmt.Sprintf("connection %s already torn down, dropping job", job.ID))
	}
}

// newSOCKSServer is a factory to create and return a global SOCKS5 server instance
func newSOCKSServer() (err error) {
	cli.Message(cli.NOTE, "Starting SOCKS5 server")
	// Create SOCKS5 server
	conf := &socks5.Config{}
	server, err = socks5.New(conf)
	if err != nil {
		return fmt.Errorf("there was an error creating a new SOCKS5 server: %s", err)
	}
	return
}

// start the SOCKS server to serve the connection
func start(id uuid.UUID) {
	cli.Message(cli.NOTE, fmt.Sprintf("Serving new SOCKS connection ID %s", id))

	connection, ok := connections.Load(id)
	if !ok {
		cli.Message(cli.WARN, fmt.Sprintf("connection %s not found", id))
		return
	}
	c := connection.(*Connection)
	defer c.teardown(id)

	err := server.ServeConn(c.In)
	if err != nil {
		cli.Message(cli.WARN, fmt.Sprintf("there was an error serving SOCKS connection %s: %s", id, err))
	}
	cli.Message(cli.DEBUG, fmt.Sprintf("Finished serving SOCKS connection ID %s", id))
}

// listen continuously for data being returned from the SOCKS server to be sent to the agent
func listen(id uuid.UUID) {
	// Listen for data on the agent-side write pipe
	connection, ok := connections.Load(id)
	if !ok {
		cli.Message(cli.WARN, fmt.Sprintf("connection %s not found", id))
		return
	}
	c := connection.(*Connection)
	defer c.teardown(id)

	j := c.Job
	job := jobs.Job{
		AgentID: j.AgentID,
		ID:      j.ID,
		Token:   j.Token,
		Type:    jobs.SOCKS,
	}

	var i int
	// Allocate read buffer once; copy to right-sized slice before sending
	buf := make([]byte, 500000)
	for {
		n, err := c.Out.Read(buf)
		cli.Message(cli.DEBUG, fmt.Sprintf("Read %d bytes from the OUTBOUND pipe with error %v", n, err))

		// Check if connection is being torn down
		select {
		case <-c.done:
			return
		default:
		}

		if err != nil {
			cli.Message(cli.WARN, fmt.Sprintf("there was an error reading from the OUTBOUND pipe: %s", err))
			return
		}

		// Copy to right-sized slice (safe: buf is reused, chunk is independent)
		chunk := make([]byte, n)
		copy(chunk, buf[:n])

		// Return data to the client
		job.Payload = jobs.Socks{
			ID:    id,
			Index: i,
			Data:  chunk,
		}
		*c.JobChan <- job
		i++
	}
}

// send continuously sends data to the SOCKS server from the SOCKS client
func send(id uuid.UUID) {
	conn, ok := connections.Load(id)
	if !ok {
		cli.Message(cli.WARN, fmt.Sprintf("connection ID %s was not found", id))
		return
	}
	c := conn.(*Connection)
	defer c.teardown(id)

	for {
		// Get SOCKS job from the channel, with done-awareness
		var job jobs.Socks
		select {
		case job = <-*c.in:
		case <-c.done:
			return
		}

		// Check to ensure the index is correct, if not, return it to the channel to be processed again
		if c.Count != job.Index {
			select {
			case *c.in <- job:
			case <-c.done:
				return
			}
			runtime.Gosched()
			continue
		}

		// If there is data, write it to the SOCKS server
		// Send data, if any, before closing the connection
		if len(job.Data) > 0 {
			c.Count++
			// Write the received data directly to the agent side pipe
			n, err := c.Out.Write(job.Data)
			if err != nil {
				cli.Message(cli.WARN, fmt.Sprintf("there was an error writing data to the SOCKS %s OUTBOUND pipe: %s", job.ID, err))
				return
			}
			cli.Message(cli.DEBUG, fmt.Sprintf("Wrote %d bytes to the SOCKS %s OUTBOUND pipe", n, job.ID))
		}

		// If the SOCKS client has sent io.EOF to close the connection
		if job.Close {
			// Mythic is sending two Close messages so the counter needs to increment on close too
			if len(job.Data) <= 0 {
				c.Count++
			}
			cli.Message(cli.NOTE, fmt.Sprintf("Closing SOCKS connection %s", job.ID))
			return
		}
	}
}
