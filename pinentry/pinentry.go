package pinentry

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"sync"
	"time"

	assuan "github.com/foxcpp/go-assuan/client"
	"github.com/foxcpp/go-assuan/pinentry"
	"github.com/psanford/tpm-fido/fprintd"
)

func New() *Pinentry {
	return &Pinentry{
		useFingerprintAuth: true, // Always use fingerprint auth
	}
}

type Pinentry struct {
	mu                sync.Mutex
	activeRequest     *request
	useFingerprintAuth bool
}

// SetUseFingerprintAuth enables or disables fingerprint authentication
func (pe *Pinentry) SetUseFingerprintAuth(use bool) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.useFingerprintAuth = use
}

type request struct {
	timeout       time.Duration
	pendingResult chan Result
	extendTimeout chan time.Duration

	challengeParam   [32]byte
	applicationParam [32]byte
}

type Result struct {
	OK    bool
	Error error
}

func (pe *Pinentry) ConfirmPresence(prompt string, challengeParam, applicationParam [32]byte) (chan Result, error) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	timeout := 2 * time.Second

	if pe.activeRequest != nil {
		if challengeParam != pe.activeRequest.challengeParam || applicationParam != pe.activeRequest.applicationParam {
			return nil, errors.New("other request already in progress")
		}

		extendTimeoutChan := pe.activeRequest.extendTimeout

		go func() {
			select {
			case extendTimeoutChan <- timeout:
			case <-time.After(timeout):
			}
		}()

		return pe.activeRequest.pendingResult, nil
	}

	pe.activeRequest = &request{
		timeout:          timeout,
		challengeParam:   challengeParam,
		applicationParam: applicationParam,
		pendingResult:    make(chan Result),
		extendTimeout:    make(chan time.Duration),
	}

	go pe.prompt(pe.activeRequest, prompt)

	return pe.activeRequest.pendingResult, nil
}

func (pe *Pinentry) prompt(req *request, prompt string) {
	// Use atomic operations for status flags
	sendResult := func(r Result) {
		select {
		case req.pendingResult <- r:
		case <-time.After(req.timeout):
			log.Printf("Warning: Client may have disappeared - timeout sending result")
		}

		pe.mu.Lock()
		pe.activeRequest = nil
		pe.mu.Unlock()
	}

	// ALWAYS use fingerprint verification
	log.Printf("Starting fingerprint verification")
	
	// Implement exponential backoff for fingerprint verification
	maxRetries := 3
	retryDelay := 500 * time.Millisecond
	
	for i := 0; i < maxRetries; i++ {
		fpResult, err := fprintd.Verify()
		
		if err == nil {
			// Return the result only if verification succeeded
			if fpResult {
				log.Printf("Fingerprint verification succeeded")
				sendResult(Result{OK: true})
				return
			}
			
			log.Printf("Fingerprint verification failed (attempt %d/%d)", i+1, maxRetries)
			
			// Not an error, but verification failed
			if i == maxRetries-1 {
				sendResult(Result{OK: false})
				return
			}
		} else {
			// Critical error - no retry
			log.Printf("Fingerprint verification error: %v", err)
			sendResult(Result{
				OK: false,
				Error: fmt.Errorf("fingerprint verification failed: %w", err),
			})
			return
		}
		
		// Exponential backoff
		time.Sleep(retryDelay)
		retryDelay *= 2
	}
}

func FindPinentryGUIPath() string {
	candidates := []string{
		"pinentry-gnome3",
		"pinentry-qt5",
		"pinentry-qt4",
		"pinentry-qt",
		"pinentry-gtk-2",
		"pinentry-x11",
		"pinentry-fltk",
	}
	for _, candidate := range candidates {
		p, _ := exec.LookPath(candidate)
		if p != "" {
			return p
		}
	}
	return ""
}

func launchPinEntry(ctx context.Context) (*pinentry.Client, *exec.Cmd, error) {
	pinEntryCmd := FindPinentryGUIPath()
	if pinEntryCmd == "" {
		log.Printf("Failed to detect gui pinentry binary. Falling back to default `pinentry`")
		pinEntryCmd = "pinentry"
	}
	cmd := exec.CommandContext(ctx, pinEntryCmd)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}

	var c pinentry.Client
	c.Session, err = assuan.Init(assuan.ReadWriteCloser{
		ReadCloser:  stdout,
		WriteCloser: stdin,
	})

	if err != nil {
		return nil, nil, err
	}
	return &c, cmd, nil
}