package test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/archive"
)

type DockerImageBuildErrorDetail struct {
	Message string `json:"message"`
}

type DockerImageBuildLogAux struct {
	ID string `json:"ID"`
}

type DockerImageBuildLog struct {
	Stream      string                       `json:"stream"`
	Aux         *DockerImageBuildLogAux      `json:"aux"`
	Error       string                       `json:"error"`
	ErrorDetail *DockerImageBuildErrorDetail `json:"errorDetail"`
}

// BuildHorcruxImage builds a Docker image for horcrux from current Dockerfile
func BuildHorcruxImage(ctx context.Context, client *client.Client) error {
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	dockerfile := "docker/horcrux/native.Dockerfile"
	opts := types.ImageBuildOptions{
		Dockerfile: dockerfile,
		Tags:       []string{signerImage + ":latest"},
	}

	tar, err := archive.TarWithOptions(filepath.Dir(dir), &archive.TarOptions{})
	if err != nil {
		panic(fmt.Errorf("error archiving project for docker: %v", err))
	}

	res, err := client.ImageBuild(ctx, tar, opts)
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(res.Body)

	for scanner.Scan() {
		dockerLogLine := &DockerImageBuildLog{}
		logLineText := scanner.Text()
		err = json.Unmarshal([]byte(logLineText), dockerLogLine)
		if err != nil {
			return err
		}
		if dockerLogLine.Stream != "" {
			fmt.Printf(dockerLogLine.Stream)
		}
		if dockerLogLine.Aux != nil {
			fmt.Printf("Image ID: %s\n", dockerLogLine.Aux.ID)
		}
		if dockerLogLine.Error != "" {
			return errors.New(dockerLogLine.Error)
		}
	}

	return scanner.Err()
}
