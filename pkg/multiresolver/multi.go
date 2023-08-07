/*multiresolver package allows you to Dial to multiple hosts/IPs as a single ClientConn.
 *
 * This was originally sourced from https://github.com/Jille/grpc-multi-resolver
 *
 * Usage: multi:///127.0.0.1:1234,dns://example.org:1234
 * Note the triple slash at the beginning.
 */
package multiresolver

import (
	"fmt"
	"net/url"
	"strings"
	"sync"

	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/serviceconfig"
)

var _ resolver.Builder = builder{}
var _ resolver.ClientConn = &partialClientConn{}
var _ resolver.Resolver = &multiResolver{}

// Register registers the multiresolver builder
func Register() {
	resolver.Register(builder{})
}

// builder is a resolver.Builder to build a multiresolver.
type builder struct{}

// Scheme declares the scheme that should be resolved by this resolver.Builder.
func (builder) Scheme() string {
	return "multi"
}

// Build builds a resolver that will resolve to multiple targets.
func (builder) Build(
	target resolver.Target,
	cc resolver.ClientConn,
	opts resolver.BuildOptions,
) (resolver.Resolver, error) {
	mr := &multiResolver{
		pccg: &partialClientConnGroup{
			cc: cc,
		},
	}

	rawTargets := strings.Split(target.Endpoint(), ",")

	for _, t := range rawTargets {
		if err := mr.resolverBuilder(t, opts); err != nil {
			mr.Close()
			return nil, err
		}
	}

	return mr, nil
}

type partialClientConnGroup struct {
	cc    resolver.ClientConn
	parts []*partialClientConn
}

func (pccg *partialClientConnGroup) updateState() error {
	s := resolver.State{}
	pccg.parts[0].mtx.Lock()
	s.ServiceConfig = pccg.parts[0].state.ServiceConfig
	s.Attributes = pccg.parts[0].state.Attributes
	pccg.parts[0].mtx.Unlock()
	for _, p := range pccg.parts {
		p.mtx.Lock()
		s.Addresses = append(s.Addresses, p.state.Addresses...)
		p.mtx.Unlock()
	}
	return pccg.cc.UpdateState(s)
}

type partialClientConn struct {
	parent *partialClientConnGroup

	mtx   sync.Mutex
	state resolver.State
}

// UpdateState updates the state of the ClientConn appropriately.
func (cc *partialClientConn) UpdateState(s resolver.State) error {
	cc.mtx.Lock()
	cc.state = s
	cc.mtx.Unlock()
	return cc.parent.updateState()
}

// ReportError notifies the ClientConn that the Resolver encountered an
// error.  The ClientConn will notify the load balancer and begin calling
// ResolveNow on the Resolver with exponential backoff.
func (cc *partialClientConn) ReportError(err error) {
	cc.parent.cc.ReportError(err)
}

// NewAddress is called by resolver to notify ClientConn a new list
// of resolved addresses.
// The address list should be the complete list of resolved addresses.
//
// Deprecated: Use UpdateState instead.
func (cc *partialClientConn) NewAddress(addresses []resolver.Address) {
	cc.mtx.Lock()
	cc.state.Addresses = addresses
	cc.mtx.Unlock()
	_ = cc.parent.updateState()
}

// NewServiceConfig is called by resolver to notify ClientConn a new
// service config. The service config should be provided as a json string.
//
// Deprecated: Use UpdateState instead.
func (cc *partialClientConn) NewServiceConfig(serviceConfig string) {
	cc.mtx.Lock()
	cc.state.ServiceConfig = cc.ParseServiceConfig(serviceConfig)
	cc.mtx.Unlock()
	_ = cc.parent.updateState()
}

// ParseServiceConfig parses the provided service config and returns an
// object that provides the parsed config.
func (cc *partialClientConn) ParseServiceConfig(serviceConfigJSON string) *serviceconfig.ParseResult {
	return cc.parent.cc.ParseServiceConfig(serviceConfigJSON)
}

type multiResolver struct {
	pccg     *partialClientConnGroup
	children []resolver.Resolver
}

// resolverBuilder gets the resolver builder for the specific target.
func (m *multiResolver) resolverBuilder(
	rawTarget string,
	opts resolver.BuildOptions,
) error {
	parsable := rawTarget
	if !strings.Contains(rawTarget, "://") {
		parsable = "tcp://" + rawTarget
	}

	u, err := url.Parse(parsable)
	if err != nil {
		return err
	}

	parsedTarget := resolver.Target{URL: *u}

	resolverBuilder := resolver.Get(u.Scheme)

	if resolverBuilder == nil {
		// no scheme provided for this member of the multi address, try default scheme
		u = &url.URL{
			Scheme: resolver.GetDefaultScheme(),
			Path:   rawTarget,
		}
		parsedTarget = resolver.Target{URL: *u}

		resolverBuilder = resolver.Get(u.Scheme)
		if resolverBuilder == nil {
			return fmt.Errorf("could not get resolver for default scheme: %q", u.Scheme)
		}
	}

	pcc := &partialClientConn{parent: m.pccg}
	m.pccg.parts = append(m.pccg.parts, pcc)

	resolver, err := resolverBuilder.Build(parsedTarget, pcc, opts)
	if err != nil {
		return err
	}

	m.children = append(m.children, resolver)

	return nil
}

// ResolveNow will be called by gRPC to try to resolve the target name
// again. It's just a hint, resolver can ignore this if it's not necessary.
//
// It could be called multiple times concurrently.
func (m *multiResolver) ResolveNow(opts resolver.ResolveNowOptions) {
	for _, r := range m.children {
		r.ResolveNow(opts)
	}
}

// Close closes all children resolvers within the multiResolver.
func (m *multiResolver) Close() {
	for _, r := range m.children {
		r.Close()
	}
}
