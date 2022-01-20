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
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/raft"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/libs/service"
	client "github.com/tendermint/tendermint/rpc/jsonrpc/client"
)

const (
	retainSnapshotCount = 2
)

type command struct {
	Op    string `json:"op,omitempty"`
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}

type RaftPeer struct {
	NodeID  string
	Address string
}

// Store is a simple key-value store, where all changes are made via Raft consensus.
type RaftStore struct {
	service.BaseService

	NodeID      string
	RaftDir     string
	RaftBind    string
	RaftTimeout time.Duration
	RaftPeers   []RaftPeer

	mu sync.Mutex
	m  map[string]string // The key-value store for the system.

	raft *raft.Raft // The consensus mechanism

	logger             log.Logger
	cosigner           *LocalCosigner
	thresholdValidator *ThresholdValidator
}

// New returns a new Store.
func NewRaftStore(nodeID string, directory string, bindAddress string, timeout time.Duration, logger log.Logger, cosigner *LocalCosigner, raftPeers []RaftPeer) *RaftStore {
	cosignerRaftStore := &RaftStore{
		NodeID:      nodeID,
		RaftDir:     directory,
		RaftBind:    bindAddress,
		RaftTimeout: timeout,
		m:           make(map[string]string),
		logger:      logger,
		cosigner:    cosigner,
		RaftPeers:   raftPeers,
	}

	cosignerRaftStore.BaseService = *service.NewBaseService(logger, "CosignerRaftStore", cosignerRaftStore)
	return cosignerRaftStore
}

func (s *RaftStore) SetThresholdValidator(thresholdValidator *ThresholdValidator) {
	s.thresholdValidator = thresholdValidator
}

// OnStart starts the raft server
func (s *RaftStore) OnStart() error {
	go func() {
		//defer s.raft.Shutdown()
		if err := s.Open(); err != nil {
			s.logger.Error("failed to open raft store", err.Error())
			return
		}
		if s.NodeID == "1" {
			// Wait until bootstrap node is the leader
			for s.raft.State() != raft.Leader {
				time.Sleep(1 * time.Second)
			}
			s.JoinCosigners()
		}
	}()

	return nil
}

// Open opens the store. If enableSingle is set, and there are no existing peers,
// then this node becomes the first node, and therefore leader, of the cluster.
// localID should be the server identifier for this node.
func (s *RaftStore) Open() error {
	// Setup Raft configuration.
	config := raft.DefaultConfig()
	config.LocalID = raft.ServerID(s.NodeID)
	config.LogLevel = "ERROR"

	// Setup Raft communication.
	addr, err := net.ResolveTCPAddr("tcp", s.RaftBind)
	if err != nil {
		return err
	}
	transport, err := raft.NewTCPTransport(s.RaftBind, addr, 3, 10*time.Second, os.Stderr)
	if err != nil {
		return err
	}

	// Create the snapshot store. This allows the Raft to truncate the log.
	snapshots, err := raft.NewFileSnapshotStore(s.RaftDir, retainSnapshotCount, os.Stderr)
	if err != nil {
		return fmt.Errorf("file snapshot store: %s", err)
	}

	// Create the log store and stable store.
	var logStore raft.LogStore
	var stableStore raft.StableStore
	logStore = raft.NewInmemStore()
	stableStore = raft.NewInmemStore()

	// Instantiate the Raft systems.
	ra, err := raft.NewRaft(config, (*fsm)(s), logStore, stableStore, snapshots, transport)
	if err != nil {
		return fmt.Errorf("new raft: %s", err)
	}
	s.raft = ra

	if s.NodeID == "1" {
		configuration := raft.Configuration{
			Servers: []raft.Server{
				{
					ID:      config.LocalID,
					Address: transport.LocalAddr(),
				},
			},
		}
		ra.BootstrapCluster(configuration)
	}

	return nil
}

func (s *RaftStore) JoinCosigners() {
	for _, peer := range s.RaftPeers {
		fmt.Printf("Adding node to cluster: %s %s\n", peer.NodeID, peer.Address)
		err := s.Join(peer.NodeID, peer.Address)
		if err != nil {
			s.logger.Error("Error joining cosigner to Raft cluster", peer.NodeID, err.Error())
		}
	}
}

// Get returns the value for the given key.
func (s *RaftStore) Get(key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[key], nil
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
	return &fsmSnapshot{store: o}, nil
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

func (f *fsm) shouldRetain(key string) bool {
	// HRS are handled as events only
	if key == "HRS" {
		return false
	}

	if len(key) < 9 {
		return true
	}

	// Sign Requests are handled as events only
	if key[:8] == "SignReq." {
		return false
	}
	// Drop receipts for old HRS
	if key[:8] == "EphDone." {
		keySplit := strings.Split(key, ".")
		height, err := strconv.ParseInt(keySplit[1], 10, 64)
		if err == nil {
			lastSigned := (*RaftStore)(f).thresholdValidator.GetLastSigned()
			if height == lastSigned.Height {
				round, err := strconv.ParseInt(keySplit[2], 10, 64)
				if err == nil {
					if round == lastSigned.Round {
						step, err := strconv.ParseInt(keySplit[3], 10, 8)
						if err == nil {
							if int8(step) <= lastSigned.Step {
								return false
							}
						}
					} else if round < lastSigned.Round {
						return false
					}
				}
			} else if height < lastSigned.Round {
				return false
			}
		}
	}
	return true
}

func (f *fsm) applySet(key, value string) interface{} {
	go f.handleSetEvents(key, value)
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
	store map[string]string
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
		sink.Cancel()
	}

	return err
}

func (f *fsmSnapshot) Release() {}

func (s *RaftStore) GetLeaderRPCAddress() string {
	leader := s.GetLeader()
	leaderSplit := strings.Split(string(leader), ":")
	leaderAddress := leaderSplit[0]
	return fmt.Sprintf("tcp://%s:%s", leaderAddress, "2222")
}

func (s *RaftStore) LeaderSignBlock(req RpcRaftSignBlockRequest) (*RpcRaftSignBlockResponse, error) {
	remoteClient, err := client.New(s.GetLeaderRPCAddress())
	if err != nil {
		return nil, err
	}
	params := map[string]interface{}{
		"arg": req,
	}
	result := &RpcRaftSignBlockResponse{}
	_, err = remoteClient.Call(ctx, "SignBlock", params, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *RaftStore) LeaderDelete(req RpcRaftRequest) (*RpcRaftResponse, error) {
	remoteClient, err := client.New(s.GetLeaderRPCAddress())
	if err != nil {
		return nil, err
	}
	params := map[string]interface{}{
		"arg": req,
	}
	result := &RpcRaftResponse{}
	_, err = remoteClient.Call(ctx, "Delete", params, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *RaftStore) LeaderEmitEphemeralSecretPart(req RpcRaftEmitEphemeralSecretRequest) (*RpcRaftResponse, error) {
	if s.raft.State() != raft.Leader {
		return nil, errors.New("Not raft leader")
	}
	emitKey := fmt.Sprintf("Eph.%d.%d", req.DestinationID, req.SourceID)

	ephScrtResJson, err := json.Marshal(req.EphemeralSecretPart)
	if err != nil {
		return nil, err
	}

	if err := s.Set(emitKey, string(ephScrtResJson)); err != nil {
		return nil, err
	}

	return &RpcRaftResponse{Key: emitKey}, nil
}

func (s *RaftStore) LeaderEmitEphemeralSecretPartReceipt(req RpcRaftEmitEphemeralSecretReceiptRequest) (*RpcRaftResponse, error) {
	if s.raft.State() != raft.Leader {
		return nil, errors.New("Not raft leader")
	}
	doneSharingKey := fmt.Sprintf("EphDone.%d.%d.%d.%d.%d", req.HRS.Height, req.HRS.Round, req.HRS.Step, req.DestinationID, req.SourceID)

	if err := s.Set(doneSharingKey, "true"); err != nil {
		return nil, err
	}

	return &RpcRaftResponse{Key: doneSharingKey}, nil
}

func (s *RaftStore) LeaderEmitSignature(req RpcRaftEmitSignatureRequest) (*RpcRaftResponse, error) {
	if s.raft.State() != raft.Leader {
		return nil, errors.New("Not raft leader")
	}
	signKey := fmt.Sprintf("SignRes.%d.%d.%d.%d", req.HRS.Height, req.HRS.Round, req.HRS.Step, req.SourceID)

	signJson, err := json.Marshal(req.SignResponse)
	if err != nil {
		return nil, err
	}

	if err := s.Set(signKey, string(signJson)); err != nil {
		return nil, err
	}

	return &RpcRaftResponse{Key: signKey}, nil
}

func (f *fsm) handleHRSEvent(hrsKey *HRSKey) {
	for _, peer := range f.cosigner.GetPeers() {
		peerID := peer.ID
		// needed since we are included in peers
		if peerID == f.cosigner.GetID() {
			continue
		}
		ephScrtRes, err := f.cosigner.GetEphemeralSecretPart(CosignerGetEphemeralSecretPartRequest{
			ID:     peerID,
			Height: hrsKey.Height,
			Round:  hrsKey.Round,
			Step:   hrsKey.Step,
		})
		if err != nil {
			fmt.Printf("Eph Scrt Req Error: %v\n", err)
			continue
		}
		(*RaftStore)(f).EmitEphemeralSecretPart(RpcRaftEmitEphemeralSecretRequest{
			SourceID:            f.cosigner.GetID(),
			DestinationID:       peerID,
			EphemeralSecretPart: ephScrtRes,
		})
	}
}

func (f *fsm) handleSetEvents(key, value string) {
	if key == "HRS" {
		hrsKey := &HRSKey{}
		err := json.Unmarshal([]byte(value), hrsKey)
		if err != nil {
			fmt.Printf("HRS Unmarshal Error: %v\n", err)
			return
		}
		f.handleHRSEvent(hrsKey)
		return
	}
	for _, peer := range f.cosigner.GetPeers() {
		peerWatchKey := fmt.Sprintf("Eph.%d.%d", f.cosigner.GetID(), peer.ID)
		if key == peerWatchKey {
			var ephScrtRes = &CosignerGetEphemeralSecretPartResponse{}
			err := json.Unmarshal([]byte(value), ephScrtRes)
			if err != nil {
				fmt.Printf("Eph Scrt Unmarshal Error: %v\n", err)
				continue
			}
			err = f.cosigner.SetEphemeralSecretPart(CosignerSetEphemeralSecretPartRequest{
				SourceSig:                      ephScrtRes.SourceSig,
				SourceID:                       ephScrtRes.SourceID,
				SourceEphemeralSecretPublicKey: ephScrtRes.SourceEphemeralSecretPublicKey,
				EncryptedSharePart:             ephScrtRes.EncryptedSharePart,
				Height:                         ephScrtRes.Height,
				Round:                          ephScrtRes.Round,
				Step:                           ephScrtRes.Step,
			})
			if err != nil {
				fmt.Printf("Eph Scrt Set Error: %v\n", err)
				continue
			}
			(*RaftStore)(f).EmitEphemeralSecretPartReceipt(RpcRaftEmitEphemeralSecretReceiptRequest{
				DestinationID: f.cosigner.GetID(),
				SourceID:      peer.ID,
				HRS: HRSKey{
					Height: ephScrtRes.Height,
					Round:  ephScrtRes.Round,
					Step:   ephScrtRes.Step,
				},
			})
			return
		}
	}

	signWatchKey := fmt.Sprintf("SignReq.%d", f.cosigner.GetID())
	if key == signWatchKey {
		var req = &CosignerSignRequest{}
		err := json.Unmarshal([]byte(value), req)
		signRes, err := f.cosigner.Sign(*req)
		if err != nil {
			fmt.Printf("Sign Req Error: %v\n", err)
			return
		}
		(*RaftStore)(f).EmitSignature(RpcRaftEmitSignatureRequest{
			HRS: HRSKey{
				Height: signRes.Height,
				Round:  signRes.Round,
				Step:   signRes.Step,
			},
			SourceID:     f.cosigner.GetID(),
			SignResponse: signRes,
		})
		return
	}
}

func (s *RaftStore) callLeaderRPC(method string, req interface{}) (*RpcRaftResponse, error) {
	remoteClient, err := client.New(s.GetLeaderRPCAddress())
	if err != nil {
		return nil, err
	}
	params := map[string]interface{}{
		"arg": req,
	}
	result := &RpcRaftResponse{}
	_, err = remoteClient.Call(ctx, method, params, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *RaftStore) EmitEphemeralSecretPart(req RpcRaftEmitEphemeralSecretRequest) (*RpcRaftResponse, error) {
	if s.raft.State() == raft.Leader {
		return s.LeaderEmitEphemeralSecretPart(req)
	}
	return s.callLeaderRPC("EmitEphemeralSecretPart", req)
}

func (s *RaftStore) EmitEphemeralSecretPartReceipt(req RpcRaftEmitEphemeralSecretReceiptRequest) (*RpcRaftResponse, error) {
	if s.raft.State() == raft.Leader {
		return s.LeaderEmitEphemeralSecretPartReceipt(req)
	}
	return s.callLeaderRPC("EmitEphemeralSecretPartReceipt", req)
}

func (s *RaftStore) EmitSignature(req RpcRaftEmitSignatureRequest) (*RpcRaftResponse, error) {
	if s.raft.State() == raft.Leader {
		return s.LeaderEmitSignature(req)
	}
	return s.callLeaderRPC("EmitSignature", req)
}
