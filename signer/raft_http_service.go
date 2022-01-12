package signer

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/libs/service"
)

// Store is the interface Raft-backed key-value stores must implement.
type Store interface {
	// Get returns the value for the given key.
	Get(key string) (string, error)

	// Set sets the value for the given key, via distributed consensus.
	Set(key, value string) error

	// Delete removes the given key, via distributed consensus.
	Delete(key string) error

	// Join joins the node, identitifed by nodeID and reachable at addr, to the cluster.
	Join(nodeID string, addr string) error
}

// RaftHttpService provides the HTTP server for accessing the distributed key-value store.
// It also provides the endpoint for other nodes to join an existing cluster.
type RaftHttpService struct {
	service.BaseService

	addr   string
	ln     net.Listener
	logger log.Logger

	store Store
}

// Returns an uninitialized HTTP service.
func NewRaftHttpService(addr string, store Store, logger log.Logger) *RaftHttpService {
	cosignerRaftHttpService := &RaftHttpService{
		addr:   addr,
		store:  store,
		logger: logger,
	}

	cosignerRaftHttpService.BaseService = *service.NewBaseService(logger, "CosignerRaftHttpService", cosignerRaftHttpService)
	return cosignerRaftHttpService
}

// OnStart starts the raft server
func (s *RaftHttpService) OnStart() error {
	go func() {
		defer s.Close()
		if err := s.Open(); err != nil {
			s.logger.Error("Error starting http service", err)
		}
	}()

	return nil
}

// Start starts the service.
func (s *RaftHttpService) Open() error {
	server := http.Server{
		Handler: s,
	}

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.ln = ln

	http.Handle("/", s)

	go func() {
		err := server.Serve(s.ln)
		if err != nil {
			s.logger.Error("HTTP serve", err)
		}
	}()

	return nil
}

// Close closes the service.
func (s *RaftHttpService) Close() {
	s.ln.Close()
	return
}

// ServeHTTP allows RaftHttpService to serve HTTP requests.
func (s *RaftHttpService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/key") {
		s.handleKeyRequest(w, r)
	} else if r.URL.Path == "/join" {
		s.handleJoin(w, r)
	} else {
		w.WriteHeader(http.StatusNotFound)
	}
}

func (s *RaftHttpService) handleJoin(w http.ResponseWriter, r *http.Request) {
	m := map[string]string{}
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if len(m) != 2 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	remoteAddr, ok := m["addr"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	nodeID, ok := m["id"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err := s.store.Join(nodeID, remoteAddr); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (s *RaftHttpService) handleKeyRequest(w http.ResponseWriter, r *http.Request) {
	getKey := func() string {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) != 3 {
			return ""
		}
		return parts[2]
	}

	switch r.Method {
	case "GET":
		k := getKey()
		if k == "" {
			w.WriteHeader(http.StatusBadRequest)
		}
		v, err := s.store.Get(k)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		b, err := json.Marshal(map[string]string{k: v})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		io.WriteString(w, string(b))

	case "POST":
		// Read the value from the POST body.
		m := map[string]string{}
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for k, v := range m {
			if err := s.store.Set(k, v); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

	case "DELETE":
		k := getKey()
		if k == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := s.store.Delete(k); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		s.store.Delete(k)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
	return
}

// Addr returns the address on which the RaftHttpService is listening
func (s *RaftHttpService) Addr() net.Addr {
	return s.ln.Addr()
}
