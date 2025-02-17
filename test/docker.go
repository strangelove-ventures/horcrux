package test

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/docker/cli/cli/config/configfile"
	"github.com/docker/docker/api/types"
	dockerimagetypes "github.com/docker/docker/api/types/image"
	"github.com/docker/docker/pkg/archive"
	"github.com/google/uuid"
	"github.com/moby/moby/client"
)

type DockerImageBuildErrorDetail struct {
	Message string `json:"message"`
}

type DockerImageBuildLogAux struct {
	ID string `json:"ID"`
}

type DockerImageBuildLog struct {
	Stream      string                       `json:"stream"`
	Aux         any                          `json:"aux"`
	Error       string                       `json:"error"`
	ErrorDetail *DockerImageBuildErrorDetail `json:"errorDetail"`
}

func getConfig() *configfile.ConfigFile {
	// Try to read Docker config for auth
	configFile := filepath.Join(os.Getenv("HOME"), ".docker", "config.json")
	if _, err := os.Stat(configFile); err != nil {
		return nil
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil
	}

	var config configfile.ConfigFile

	if err := json.Unmarshal(data, &config); err != nil {
		return nil
	}

	return &config
}

func getDockerClient() (*client.Client, error) {
	opts := []client.Opt{
		client.WithVersion("1.41"),            // Use a specific API version
		client.WithTimeout(120 * time.Second), // Longer timeout
	}

	return client.NewClientWithOpts(opts...)
}

// TODO: find better way for buildkit to be able to pull images
func primeDockerDaemon(ctx context.Context, client *client.Client) error {
	images := []string{
		"golang:1.24-alpine",
		"busybox:1.34.1-musl",
		"ghcr.io/strangelove-ventures/infra-toolkit:v0.0.6",
	}

	for _, image := range images {
		_, err := client.ImagePull(ctx, image, dockerimagetypes.PullOptions{})
		if err != nil {
			return fmt.Errorf("failed to pull %s: %w", image, err)
		}
	}
	return nil
}

// BuildHorcruxImage builds a Docker image for horcrux from current Dockerfile
func BuildHorcruxImage(ctx context.Context, _ *client.Client) error {
	dir, err := os.Getwd()
	if err != nil {
		return err
	}
	dockerfile := "Dockerfile"
	outputStr := "type=docker"

	opts := types.ImageBuildOptions{
		Dockerfile: dockerfile,
		Tags:       []string{signerImage + ":latest"},
		BuildArgs: map[string]*string{
			"output": &outputStr,
		},
		Version: types.BuilderBuildKit,
		BuildID: fmt.Sprintf("buildkit-%s", uuid.New().String()),
	}

	tar, err := archive.TarWithOptions(filepath.Dir(dir), &archive.TarOptions{})
	if err != nil {
		panic(fmt.Errorf("error archiving project for docker: %v", err))
	}

	client, err := getDockerClient()
	if err != nil {
		return err
	}

	if err := primeDockerDaemon(ctx, client); err != nil {
		return err
	}

	os.Setenv("BUILDKIT_PROGRESS", "plain")

	res, err := client.ImageBuild(ctx, tar, opts)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	scanner := bufio.NewScanner(res.Body)

	for scanner.Scan() {
		dockerLogLine := &DockerImageBuildLog{}
		logLineText := scanner.Text()
		err = json.Unmarshal([]byte(logLineText), dockerLogLine)
		if err != nil {
			return err
		}
		if dockerLogLine.Stream != "" {
			fmt.Printf("%s", dockerLogLine.Stream)
		}
		if dockerLogLine.Aux != nil {
			if auxStr, ok := dockerLogLine.Aux.(string); ok {
				log, err := base64.StdEncoding.DecodeString(auxStr)
				if err != nil {
					return err
				}
				fmt.Printf("%s", log)
			} else if auxObj, ok := dockerLogLine.Aux.(*DockerImageBuildLogAux); ok {
				fmt.Printf("%s", auxObj.ID)
			}
		}
		if dockerLogLine.Error != "" {
			return errors.New(dockerLogLine.Error)
		}
	}

	return scanner.Err()
}
