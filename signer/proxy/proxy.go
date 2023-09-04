package proxy

import (
	"net"

	cometcrypto "github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	cometcryptoed25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cometlog "github.com/cometbft/cometbft/libs/log"
	cometnet "github.com/cometbft/cometbft/libs/net"
	cometos "github.com/cometbft/cometbft/libs/os"
	cometservice "github.com/cometbft/cometbft/libs/service"
	cometprotoprivval "github.com/cometbft/cometbft/proto/tendermint/privval"
	cometproto "github.com/cometbft/cometbft/proto/tendermint/types"
	"github.com/strangelove-ventures/horcrux/signer"
	"github.com/strangelove-ventures/horcrux/signer/proxy/privval"
)

var _ signer.PrivValidator = (*PrivValProxy)(nil)

type PrivValProxy struct {
	sl *privval.SignerListenerEndpoint
}

func NewPrivValProxy(sl *privval.SignerListenerEndpoint) *PrivValProxy {
	return &PrivValProxy{sl: sl}
}

func (p *PrivValProxy) SignVote(chainID string, vote *cometproto.Vote) error {
	req := cometprotoprivval.Message{
		Sum: &cometprotoprivval.Message_SignVoteRequest{
			SignVoteRequest: &cometprotoprivval.SignVoteRequest{
				ChainId: chainID,
				Vote:    vote,
			},
		},
	}

	res, err := p.sl.SendRequest(req)
	if err != nil {
		return err
	}

	signed := res.GetSignedVoteResponse()

	*vote = signed.Vote

	return nil
}

func (p *PrivValProxy) SignProposal(chainID string, proposal *cometproto.Proposal) error {
	req := cometprotoprivval.Message{
		Sum: &cometprotoprivval.Message_SignProposalRequest{
			SignProposalRequest: &cometprotoprivval.SignProposalRequest{
				ChainId:  chainID,
				Proposal: proposal,
			},
		},
	}

	res, err := p.sl.SendRequest(req)
	if err != nil {
		return err
	}

	signed := res.GetSignedProposalResponse()

	*proposal = signed.Proposal

	return nil
}

func (p *PrivValProxy) GetPubKey(chainID string) (cometcrypto.PubKey, error) {
	req := cometprotoprivval.Message{
		Sum: &cometprotoprivval.Message_PubKeyRequest{
			PubKeyRequest: &cometprotoprivval.PubKeyRequest{
				ChainId: chainID,
			},
		},
	}

	res, err := p.sl.SendRequest(req)
	if err != nil {
		return nil, err
	}

	pub := res.GetPubKeyResponse().PubKey.GetEd25519()

	return cometcryptoed25519.PubKey(pub), nil
}

func (p *PrivValProxy) Stop() {
	_ = p.sl.Stop()
}

func NewSignerListenerEndpoint(logger cometlog.Logger, addr string) *privval.SignerListenerEndpoint {
	proto, address := cometnet.ProtocolAndAddress(addr)

	ln, err := net.Listen(proto, address)
	logger.Info("SignerListener: Listening", "proto", proto, "address", address)
	if err != nil {
		panic(err)
	}

	var listener net.Listener

	if proto == "unix" {
		unixLn := privval.NewUnixListener(ln)
		listener = unixLn
	} else {
		tcpLn := privval.NewTCPListener(ln, ed25519.GenPrivKey())
		listener = tcpLn
	}

	return privval.NewSignerListenerEndpoint(
		logger,
		listener,
	)
}

func WaitAndTerminate(logger cometlog.Logger, listener cometservice.Service, sentries map[string]*signer.ReconnRemoteSigner) {
	done := make(chan struct{})
	cometos.TrapSignal(logger, func() {
		for _, s := range sentries {
			err := s.Stop()
			if err != nil {
				panic(err)
			}
		}
		if err := listener.Stop(); err != nil {
			panic(err)
		}
		close(done)
	})
	<-done
}
