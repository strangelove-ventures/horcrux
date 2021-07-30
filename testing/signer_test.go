package testing

import (
	"github.com/ory/dockertest"
	"github.com/ory/dockertest/docker"
	"testing"
)

var (
	imageName = "horcrux-test"
	imageVer = "v0.1.0"
	dockerFile = "./docker/horcrux/Dockerfile"
	ctxDir = "/home/anon/go/src/github.com/jackzampolin/horcrux/"
)

type TestSigner struct {
	Home string
	Index int
	Pool         *dockertest.Pool
	Container    *docker.Container
	t            *testing.T
}

func (ts *TestSigner) StartContainer() error {

	return nil
}

func (ts *TestSigner) StopContainer() error {
	return nil
}

func (ts *TestSigner) CreateContainer() error {
	return nil
}

func (ts *TestSigner) InitHomeDir() error {
	return nil
}

func (ts *TestSigner) HomeDir() string {
	return ""
}

func (ts *TestSigner) CreateConfig() error {
	return nil
}

func (ts *TestSigner) CopyKeyShare(tn *TestNode) error {
	return nil
}