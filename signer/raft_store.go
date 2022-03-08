// Provides a simple distributed key-value store. The keys and
// associated values are changed via distributed consensus, meaning that the
// values are changed only when a majority of nodes in the cluster agree on
// the new value.
//
// Distributed consensus is provided via the Raft algorithm, specifically the
// Hashicorp implementation.
package signer

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Jille/raft-grpc-leader-rpc/leaderhealth"
	gRPCTransport "github.com/Jille/raft-grpc-transport"
	"github.com/Jille/raftadmin"
	"github.com/hashicorp/raft"
	boltdb "github.com/hashicorp/raft-boltdb"
	proto "github.com/strangelove-ventures/horcrux/signer/proto"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/libs/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
)

const (
	retainSnapshotCount = 2
)

type command struct {
	Op    string `json:"op,omitempty"`
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}

// Store is a simple key-value store, where all changes are made via Raft consensus.
type RaftStore struct {
	service.BaseService

	NodeID      string
	RaftDir     string
	RaftBind    string
	RaftTimeout time.Duration
	Peers       []Cosigner

	mu sync.Mutex
	m  map[string]string // The key-value store for the system.

	raft *raft.Raft // The consensus mechanism

	logger             log.Logger
	cosigner           *LocalCosigner
	thresholdValidator *ThresholdValidator
}

// New returns a new Store.
func NewRaftStore(
	nodeID string, directory string, bindAddress string, timeout time.Duration,
	logger log.Logger, cosigner *LocalCosigner, raftPeers []Cosigner) *RaftStore {
	cosignerRaftStore := &RaftStore{
		NodeID:      nodeID,
		RaftDir:     directory,
		RaftBind:    bindAddress,
		RaftTimeout: timeout,
		m:           make(map[string]string),
		logger:      logger,
		cosigner:    cosigner,
		Peers:       raftPeers,
	}

	cosignerRaftStore.BaseService = *service.NewBaseService(logger, "CosignerRaftStore", cosignerRaftStore)
	return cosignerRaftStore
}

func (s *RaftStore) SetThresholdValidator(thresholdValidator *ThresholdValidator) {
	s.thresholdValidator = thresholdValidator
}

func (s *RaftStore) init() error {
	host := p2pURLToRaftAddress(s.RaftBind)
	_, port, err := net.SplitHostPort(host)
	if err != nil {
		return fmt.Errorf("failed to parse local address: %s, %v", host, err)
	}
	sock, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		return err
	}
	transportManager, err := s.Open()
	if err != nil {
		return err
	}
	grpcServer := grpc.NewServer()
	proto.RegisterCosignerGRPCServer(grpcServer, &GRPCServer{
		cosigner:           s.cosigner,
		thresholdValidator: s.thresholdValidator,
		raftStore:          s,
	})
	transportManager.Register(grpcServer)
	leaderhealth.Setup(s.raft, grpcServer, []string{"Leader"})
	raftadmin.Register(grpcServer, s.raft)
	reflection.Register(grpcServer)
	if err := grpcServer.Serve(sock); err != nil {
		return err
	}
	return nil
}

// OnStart starts the raft server
func (s *RaftStore) OnStart() error {
	go func() {
		err := s.init()
		if err != nil {
			panic(err)
		}
	}()

	return nil
}

func p2pURLToRaftAddress(p2pURL string) string {
	url, err := url.Parse(p2pURL)
	if err != nil {
		return p2pURL
	}
	return url.Host
}

// Open opens the store. If enableSingle is set, and there are no existing peers,
// then this node becomes the first node, and therefore leader, of the cluster.
// localID should be the server identifier for this node.
func (s *RaftStore) Open() (*gRPCTransport.Manager, error) {
	// Setup Raft configuration.
	config := raft.DefaultConfig()
	config.LocalID = raft.ServerID(s.NodeID)
	config.LogLevel = "ERROR"

	// Create the snapshot store. This allows the Raft to truncate the log.
	snapshots, err := raft.NewFileSnapshotStore(s.RaftDir, retainSnapshotCount, os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("file snapshot store: %s", err)
	}

	// Create the log store and stable store.
	logStoreFile := filepath.Join(s.RaftDir, "logs.dat")
	logStore, err := boltdb.NewBoltStore(logStoreFile)
	if err != nil {
		return nil, fmt.Errorf(`boltdb.NewBoltStore(%q): %v`, logStoreFile, err)
	}

	stableStoreFile := filepath.Join(s.RaftDir, "stable.dat")
	stableStore, err := boltdb.NewBoltStore(stableStoreFile)
	if err != nil {
		return nil, fmt.Errorf(`boltdb.NewBoltStore(%q): %v`, stableStoreFile, err)
	}

	raftAddress := raft.ServerAddress(p2pURLToRaftAddress(s.RaftBind))

	// Setup Raft communication.
	transportManager := gRPCTransport.New(raftAddress, []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	})

	// Instantiate the Raft systems.
	ra, err := raft.NewRaft(config, (*fsm)(s), logStore, stableStore, snapshots, transportManager.Transport())
	if err != nil {
		return nil, fmt.Errorf("new raft: %s", err)
	}
	s.raft = ra

	configuration := raft.Configuration{
		Servers: []raft.Server{
			{
				ID:      raft.ServerID(s.NodeID),
				Address: raftAddress,
			},
		},
	}
	for _, peer := range s.Peers {
		configuration.Servers = append(configuration.Servers, raft.Server{
			ID:      raft.ServerID(fmt.Sprint(peer.GetID())),
			Address: raft.ServerAddress(p2pURLToRaftAddress(peer.GetAddress())),
		})
	}
	s.raft.BootstrapCluster(configuration)

	return transportManager, nil
}

// Get returns the value for the given key.
func (s *RaftStore) Get(key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[key], nil
}

func (s *RaftStore) Emit(key string, value interface{}) error {
	valueJSON, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.Set(key, string(valueJSON))
}

// Set sets the value for the given key.
func (s *RaftStore) Set(key, value string) error {
	if s.raft.State() != raft.Leader {
		return fmt.Errorf("not leader")
	}

	c := &command{
		Op:    "set",
		Key:   key,
		Value: value,
	}
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}

	f := s.raft.Apply(b, s.RaftTimeout)
	return f.Error()
}

// Delete deletes the given key.
func (s *RaftStore) Delete(key string) error {
	if s.raft.State() != raft.Leader {
		return fmt.Errorf("not leader")
	}

	c := &command{
		Op:  "delete",
		Key: key,
	}
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}

	f := s.raft.Apply(b, s.RaftTimeout)
	return f.Error()
}

// Join joins a node, identified by nodeID and located at addr, to this store.
// The node must be ready to respond to Raft communications at that address.
func (s *RaftStore) Join(nodeID, addr string) error {
	configFuture := s.raft.GetConfiguration()
	if err := configFuture.Error(); err != nil {
		s.logger.Error("failed to get raft configuration", err)
		return err
	}

	for _, srv := range configFuture.Configuration().Servers {
		// If a node already exists with either the joining node's ID or address,
		// that node may need to be removed from the config first.
		if srv.ID == raft.ServerID(nodeID) || srv.Address == raft.ServerAddress(addr) {
			// However if *both* the ID and the address are the same, then nothing -- not even
			// a join operation -- is needed.
			if srv.Address == raft.ServerAddress(addr) && srv.ID == raft.ServerID(nodeID) {
				s.logger.Error("node already member of cluster, ignoring join request", nodeID, addr)
				return nil
			}

			future := s.raft.RemoveServer(srv.ID, 0, 0)
			if err := future.Error(); err != nil {
				return fmt.Errorf("error removing existing node %s at %s: %s", nodeID, addr, err)
			}
		}
	}

	f := s.raft.AddVoter(raft.ServerID(nodeID), raft.ServerAddress(addr), 0, 0)
	if f.Error() != nil {
		return f.Error()
	}
	s.logger.Info("node joined successfully", nodeID, addr)
	return nil
}

func (s *RaftStore) GetLeader() raft.ServerAddress {
	return s.raft.Leader()
}

type fsm RaftStore

// Apply applies a Raft log entry to the key-value store.
func (f *fsm) Apply(l *raft.Log) interface{} {
	var c command
	if err := json.Unmarshal(l.Data, &c); err != nil {
		f.logger.Error("failed to unmarshal command", err.Error())
		return nil
	}

	switch c.Op {
	case "set":
		return f.applySet(c.Key, c.Value)
	case "delete":
		return f.applyDelete(c.Key)
	default:
		f.logger.Error("unrecognized command op", c.Op)
		return nil
	}
}

// Snapshot returns a snapshot of the key-value store.
func (f *fsm) Snapshot() (raft.FSMSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Clone the map.
	o := make(map[string]string)
	for k, v := range f.m {
		o[k] = v
	}
	return &fsmSnapshot{store: o, logger: f.logger}, nil
}

// Restore stores the key-value store to a previous state.
func (f *fsm) Restore(rc io.ReadCloser) error {
	o := make(map[string]string)
	if err := json.NewDecoder(rc).Decode(&o); err != nil {
		return err
	}

	// Set the state from the snapshot, no lock required according to
	// Hashicorp docs.
	f.m = o
	return nil
}

func (f *fsm) applySet(key, value string) interface{} {
	eventHandler := f.getEventHandler(key)
	if eventHandler != nil {
		eventHandler(value)
	}
	if !f.shouldRetain(key) {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[key] = value
	return nil
}

func (f *fsm) applyDelete(key string) interface{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.m, key)
	return nil
}

type fsmSnapshot struct {
	store  map[string]string
	logger log.Logger
}

func (f *fsmSnapshot) Persist(sink raft.SnapshotSink) error {
	err := func() error {
		// Encode data.
		b, err := json.Marshal(f.store)
		if err != nil {
			return err
		}

		// Write data to sink.
		if _, err := sink.Write(b); err != nil {
			return err
		}

		// Close the sink.
		return sink.Close()
	}()

	if err != nil {
		f.logger.Error("Snapshot persist error", err.Error())
		sinkErr := sink.Cancel()
		if sinkErr != nil {
			f.logger.Error("Error cancelling sink", sinkErr.Error())
		}
	}

	return err
}

func (f *fsmSnapshot) Release() {}
