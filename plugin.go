package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/appleboy/com/random"
	"github.com/appleboy/easyssh-proxy"
	"github.com/fatih/color"
)

var (
	errMissingHost           = errors.New("Error: missing server host")
	errMissingPasswordOrKey  = errors.New("Error: can't connect without a private SSH key or password")
	errSetPasswordandKey     = errors.New("can't set password and key at the same time")
	errMissingSourceOrTarget = errors.New("missing source or target config")
)

type (
	// Repo information.
	Repo struct {
		Owner string
		Name  string
	}

	// Build information.
	Build struct {
		Event   string
		Number  int
		Commit  string
		Message string
		Branch  string
		Author  string
		Status  string
		Link    string
	}

	// Config for the plugin.
	Config struct {
		Host              []string
		Port              string
		Username          string
		Password          string
		Key               string
		Passphrase        string
		Fingerprint       string
		KeyPath           string
		Timeout           time.Duration
		CommandTimeout    time.Duration
		Target            []string
		Source            []string
		Ignore        		string
		Remove            bool
		StripComponents   int
		TarExec           string
		TarTmpPath        string
		Proxy             easyssh.DefaultConfig
		Debug             bool
		Overwrite         bool
		Ciphers           []string
		UseInsecureCipher bool
	}

	// Plugin values.
	Plugin struct {
		Repo     Repo
		Build    Build
		Config   Config
		DestFile string
	}

	copyError struct {
		host    string
		message string
	}
)

func (e copyError) Error() string {
	return fmt.Sprintf("error copy file to dest: %s, error message: %s\n", e.host, e.message)
}

func trimPath(keys []string) []string {
	var newKeys []string

	for _, value := range keys {
		value = strings.Trim(value, " ")
		if len(value) == 0 {
			continue
		}

		newKeys = append(newKeys, value)
	}

	return newKeys
}

func loadIgnoreFile(ignoreFile string, list fileList) fileList {
	// TODO: detect if ignoreFile exist
	// TODO: Load it
	// TODO: Read line by line
	// TODO: append to list.Ignore

	

	// fmt.Println("readFileWithReadString")
	dir, err := os.Getwd()
	if err != nil {
		fmt.Println("--error or", ignoreFile)
		return list
	}

	ignoreFullPath := path.Join(dir, ignoreFile)
	file, err := os.Open(ignoreFullPath)
	if err != nil {
		fmt.Println("--error load", ignoreFullPath)
		return list
	}
	defer file.Close()

	// Start reading from the file with a reader.
	reader := bufio.NewReader(file)
	var line string
	for {
			line, err = reader.ReadString('\n')
			if err != nil && err != io.EOF {
					break
			}

			// Process the line here.
			ignorePath := strings.Trim(line, " ")
			list.Ignore = append(list.Ignore, ignorePath)
			if err != nil {
					break
			}
	}

	if err != io.EOF {
			fmt.Println(" > Failed with error: %v\n", err)
			return list
	}

	return list
}

func globList(paths []string) fileList {
	var list fileList
	fmt.Printf("--path %v", paths)
	fmt.Println("-- --")
	for _, pattern := range paths {
		ignore := false
		pattern = strings.Trim(pattern, " ")
		if string(pattern[0]) == "!" {
			pattern = pattern[1:]
			ignore = true
		}
		matches, err := filepath.Glob(pattern)
		if err != nil {
			fmt.Printf("Glob error for %q: %s\n", pattern, err)
			continue
		}

		if ignore {
			list.Ignore = append(list.Ignore, matches...)
		} else {
			list.Source = append(list.Source, matches...)
		}
	}

	return list
}

func buildArgs(tar string, files fileList) []string {
	args := []string{}
	if len(files.Ignore) > 0 {
		for _, v := range files.Ignore {
			args = append(args, "--exclude")
			args = append(args, v)
		}
	}

	fmt.Printf("--tar args %v", files.Ignore)
	args = append(args, "-cf")
	args = append(args, getRealPath(tar))
	args = append(args, files.Source...)
	return args
}

func (p Plugin) log(host string, message ...interface{}) {
	if count := len(p.Config.Host); count == 1 {
		fmt.Printf("%s", fmt.Sprintln(message...))
	} else {
		fmt.Printf("%s: %s", host, fmt.Sprintln(message...))
	}
}

func (p *Plugin) removeDestFile(ssh *easyssh.MakeConfig) error {
	p.log(ssh.Server, "remove file", p.DestFile)
	_, errStr, _, err := ssh.Run(fmt.Sprintf("rm -rf %s", p.DestFile), p.Config.CommandTimeout)

	if err != nil {
		return err
	}

	if errStr != "" {
		return errors.New(errStr)
	}

	return nil
}

func (p *Plugin) removeAllDestFile() error {
	for _, host := range p.Config.Host {
		ssh := &easyssh.MakeConfig{
			Server:            host,
			User:              p.Config.Username,
			Password:          p.Config.Password,
			Port:              p.Config.Port,
			Key:               p.Config.Key,
			KeyPath:           p.Config.KeyPath,
			Passphrase:        p.Config.Passphrase,
			Timeout:           p.Config.Timeout,
			Ciphers:           p.Config.Ciphers,
			Fingerprint:       p.Config.Fingerprint,
			UseInsecureCipher: p.Config.UseInsecureCipher,
			Proxy: easyssh.DefaultConfig{
				Server:            p.Config.Proxy.Server,
				User:              p.Config.Proxy.User,
				Password:          p.Config.Proxy.Password,
				Port:              p.Config.Proxy.Port,
				Key:               p.Config.Proxy.Key,
				KeyPath:           p.Config.Proxy.KeyPath,
				Passphrase:        p.Config.Proxy.Passphrase,
				Timeout:           p.Config.Proxy.Timeout,
				Ciphers:           p.Config.Proxy.Ciphers,
				Fingerprint:       p.Config.Proxy.Fingerprint,
				UseInsecureCipher: p.Config.Proxy.UseInsecureCipher,
			},
		}

		// remove tar file
		err := p.removeDestFile(ssh)
		if err != nil {
			return err
		}
	}

	return nil
}

type fileList struct {
	Ignore []string
	Source []string
}

func (p *Plugin) buildArgs(target string) []string {
	args := []string{}

	args = append(args,
		p.Config.TarExec,
		"-xf",
		p.DestFile,
	)

	if p.Config.StripComponents > 0 {
		args = append(args, "--strip-components")
		args = append(args, strconv.Itoa(p.Config.StripComponents))
	}

	if p.Config.Overwrite {
		args = append(args, "--overwrite")
	}

	args = append(args,
		"-C",
		target,
	)

	return args
}

// Exec executes the plugin.
func (p *Plugin) Exec() error {
	if len(p.Config.Host) == 0 {
		return errMissingHost
	}

	if len(p.Config.Key) == 0 && len(p.Config.Password) == 0 && len(p.Config.KeyPath) == 0 {
		return errMissingPasswordOrKey
	}

	if len(p.Config.Key) != 0 && len(p.Config.Password) != 0 {
		return errSetPasswordandKey
	}

	if len(p.Config.Source) == 0 || len(p.Config.Target) == 0 {
		return errMissingSourceOrTarget
	}

	
	fmt.Println("--ignore %v", p.Config.Ignore)

	files := globList(trimPath(p.Config.Source))
	files = loadIgnoreFile(p.Config.Ignore, files)
	p.DestFile = fmt.Sprintf("%s.tar", random.String(10))

	// create a temporary file for the archive
	dir, err := ioutil.TempDir("", "")
	if err != nil {
		return err
	}
	tar := filepath.Join(dir, p.DestFile)

	// run archive command
	fmt.Println("tar all files into " + tar)
	args := buildArgs(tar, files)
	cmd := exec.Command(p.Config.TarExec, args...)
	if p.Config.Debug {
		fmt.Println("$", strings.Join(cmd.Args, " "))
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	wg := sync.WaitGroup{}
	wg.Add(len(p.Config.Host))
	errChannel := make(chan error)
	finished := make(chan struct{})
	for _, host := range p.Config.Host {
		go func(host string) {
			// Create MakeConfig instance with remote username, server address and path to private key.
			ssh := &easyssh.MakeConfig{
				Server:            host,
				User:              p.Config.Username,
				Password:          p.Config.Password,
				Port:              p.Config.Port,
				Key:               p.Config.Key,
				KeyPath:           p.Config.KeyPath,
				Passphrase:        p.Config.Passphrase,
				Timeout:           p.Config.Timeout,
				Ciphers:           p.Config.Ciphers,
				Fingerprint:       p.Config.Fingerprint,
				UseInsecureCipher: p.Config.UseInsecureCipher,
				Proxy: easyssh.DefaultConfig{
					Server:            p.Config.Proxy.Server,
					User:              p.Config.Proxy.User,
					Password:          p.Config.Proxy.Password,
					Port:              p.Config.Proxy.Port,
					Key:               p.Config.Proxy.Key,
					KeyPath:           p.Config.Proxy.KeyPath,
					Passphrase:        p.Config.Proxy.Passphrase,
					Timeout:           p.Config.Proxy.Timeout,
					Ciphers:           p.Config.Proxy.Ciphers,
					Fingerprint:       p.Config.Proxy.Fingerprint,
					UseInsecureCipher: p.Config.Proxy.UseInsecureCipher,
				},
			}

			// upload file to the tmp path
			p.DestFile = fmt.Sprintf("%s%s", p.Config.TarTmpPath, p.DestFile)

			// Call Scp method with file you want to upload to remote server.
			p.log(host, "scp file to server.")
			err := ssh.Scp(tar, p.DestFile)

			if err != nil {
				errChannel <- copyError{host, err.Error()}
				return
			}

			for _, target := range p.Config.Target {
				// remove target before upload data
				if p.Config.Remove {
					p.log(host, "Remove target folder:", target)

					_, _, _, err := ssh.Run(fmt.Sprintf("rm -rf %s", target), p.Config.CommandTimeout)

					if err != nil {
						errChannel <- err
						return
					}
				}

				// mkdir path
				p.log(host, "create folder", target)
				_, errStr, _, err := ssh.Run(fmt.Sprintf("mkdir -p %s", target), p.Config.CommandTimeout)
				if err != nil {
					errChannel <- err
					return
				}

				if len(errStr) != 0 {
					errChannel <- fmt.Errorf(errStr)
					return
				}

				// untar file
				p.log(host, "untar file", p.DestFile)
				commamd := strings.Join(p.buildArgs(target), " ")
				if p.Config.Debug {
					fmt.Println("$", commamd)
				}
				outStr, errStr, _, err := ssh.Run(commamd, p.Config.CommandTimeout)

				if outStr != "" {
					p.log(host, "output: ", outStr)
				}

				if errStr != "" {
					p.log(host, "error: ", errStr)
				}

				if err != nil {
					errChannel <- err
					return
				}
			}

			// remove tar file
			err = p.removeDestFile(ssh)
			if err != nil {
				errChannel <- err
				return
			}

			wg.Done()

		}(host)
	}

	go func() {
		wg.Wait()
		close(finished)
	}()

	select {
	case <-finished:
	case err := <-errChannel:
		if err != nil {
			c := color.New(color.FgRed)
			c.Println("drone-scp error: ", err)
			if _, ok := err.(copyError); !ok {
				fmt.Println("drone-scp rollback: remove all target tmp file")
				p.removeAllDestFile()
			}
			return err
		}
	}

	fmt.Println("===================================================")
	fmt.Println("✅ Successfully executed transfer data to all host")
	fmt.Println("===================================================")

	return nil
}
