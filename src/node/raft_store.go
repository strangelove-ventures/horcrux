// Provides a simple distributed key-value store. The keys and
// associated values are changed via distributed consensus, meaning that the
// values are changed only when a majority of cosigner in the cluster agree on
// the new value.
//
// Distributed consensus is provided via the Raft algorithm, specifically the
// Hashicorp implementation.
package node

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/strangelove-ventures/horcrux/src/cosigner"

	"github.com/strangelove-ventures/horcrux/src/types"

	"github.com/Jille/raft-grpc-leader-rpc/leaderhealth"
	raftgrpctransport "github.com/Jille/raft-grpc-transport"
	"github.com/Jille/raftadmin"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/libs/service"
	"github.com/hashicorp/raft"
	boltdb "github.com/hashicorp/raft-boltdb/v2"

	// "github.com/strangelove-ventures/horcrux/src/proto"
	"github.com/strangelove-ventures/horcrux/proto/strangelove/proto"

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

// RaftStore is a simple key-value store, where all changes are made via Raft consensus.
// RafStore implements ILeader.
type RaftStore struct {
	service.BaseService

	NodeID      string
	RaftDir     string
	RaftBind    string
	RaftTimeout time.Duration
	// Cosigners   []ICosigner

	mu sync.Mutex
	m  map[string]string // The key-value store for the system.

	raft *raft.Raft // The consensus mechanism

	logger log.Logger
	// mycosigner         *cosigner.LocalCosigner
	thresholdValidator *ThresholdValidator
}

// New returns a new Store.
func NewRaftStore(
	nodeID string, directory string, bindAddress string, timeout time.Duration,
	logger log.Logger, cosigner *cosigner.LocalCosigner, cosigners []ICosigner) *RaftStore {
	cosignerRaftStore := &RaftStore{
		NodeID:      nodeID,
		RaftDir:     directory,
		RaftBind:    bindAddress,
		RaftTimeout: timeout,
		m:           make(map[string]string),
		logger:      logger,
		// mycosigner:  cosigner,
		// Cosigners:   cosigners,
	}

	cosignerRaftStore.BaseService = *service.NewBaseService(logger, "CosignerRaftStore", cosignerRaftStore)
	return cosignerRaftStore
}

func (s *RaftStore) SetThresholdValidator(thresholdValidator *ThresholdValidator, mycosigner *cosigner.LocalCosigner) {
	s.thresholdValidator = thresholdValidator
	s.thresholdValidator.mpc.MyCosigner = mycosigner // TODO: Refactor out the use of cosigner.
}

// TODO: Should move away from this initilisation method
// and instead use a "service" framework.
func (s *RaftStore) init() error {
	host := p2pURLToRaftAddress(s.RaftBind)
	_, port, err := net.SplitHostPort(host)
	if err != nil {
		return fmt.Errorf("failed to parse local address: %s, %v", host, err)
	}
	s.logger.Info("Local Raft Listening", "port", port)
	sock, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		return err
	}
	transportManager, err := s.Open()
	if err != nil {
		return err
	}
	grpcServer := grpc.NewServer()
	// TODO: RegisterCosignerServer
	// proto.RegisterCosignerServer(grpcServer, NewNodeGRPCServer(s.thresholdValidator, s))
	proto.RegisterNodeServiceServer(grpcServer, NewNodeGRPCServer(s.thresholdValidator, s))
	transportManager.Register(grpcServer)
	leaderhealth.Setup(s.raft, grpcServer, []string{"Leader"})
	raftadmin.Register(grpcServer, s.raft)
	reflection.Register(grpcServer)
	return grpcServer.Serve(sock)
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
func (s *RaftStore) Open() (*raftgrpctransport.Manager, error) {
	// Setup Raft configuration.
	config := raft.DefaultConfig()
	config.LocalID = raft.ServerID(s.NodeID)
	config.LogLevel = "ERROR"
	config.ElectionTimeout = s.RaftTimeout
	config.HeartbeatTimeout = s.RaftTimeout
	config.LeaderLeaseTimeout = s.RaftTimeout / 2

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
	transportManager := raftgrpctransport.New(raftAddress, []grpc.DialOption{
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
	for _, c := range s.thresholdValidator.mpc.peerCosigners {
		configuration.Servers = append(configuration.Servers, raft.Server{
			ID:      raft.ServerID(fmt.Sprint(c.GetIndex())), // TODO: Refactor out the use of cosigner.
			Address: raft.ServerAddress(p2pURLToRaftAddress(c.GetAddress())),
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
	if !s.IsLeader() {
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
		// If a node already exists with either the joining node's Index or address,
		// that node may need to be removed from the config first.
		if srv.ID == raft.ServerID(nodeID) || srv.Address == raft.ServerAddress(addr) {
			// However if *both* the Index and the address are the same, then nothing -- not even
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

func (s *RaftStore) IsLeader() bool {
	if s == nil || s.raft == nil {
		return false
	}
	return s.raft.State() == raft.Leader
}

func (s *RaftStore) GetLeader() int {
	if s == nil || s.raft == nil {
		return -1
	}
	_, leaderID := s.raft.LeaderWithID()
	if leaderID == "" {
		return -1
	}
	id, err := strconv.Atoi(string(leaderID))
	if err != nil {
		return -1
	}
	return id
}

func (s *RaftStore) ShareSigned(lss types.ChainSignStateConsensus) error {
	return s.Emit(raftEventLSS, lss)
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
