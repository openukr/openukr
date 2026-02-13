/*
Copyright 2026 openUKR Contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package publish

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	openukrv1alpha1 "github.com/openukr/openukr/api/v1alpha1"
	"github.com/openukr/openukr/pkg/crypto"
)

// HTTPPublisher publishes public keys via HTTP/HTTPS POST.
type HTTPPublisher struct {
	k8sClient client.Client
	client    *http.Client
}

// NewHTTPPublisher creates a new HTTP publisher.
func NewHTTPPublisher(k8sClient client.Client) *HTTPPublisher {
	return &HTTPPublisher{
		k8sClient: k8sClient,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Publish POSTs the public key (PEM format) to the configured endpoint.
// Config required: "endpoint" (URL).
func (p *HTTPPublisher) Publish(ctx context.Context, target openukrv1alpha1.PublishTarget, kp *crypto.KeyPair) error {
	endpoint, ok := target.Config["endpoint"]
	if !ok || endpoint == "" {
		return fmt.Errorf("missing 'endpoint' in config")
	}

	// [SEC:T-2] Validate URL scheme — HTTPS required unless explicitly skipped
	isInsecure := target.TLS != nil && target.TLS.InsecureSkipVerify
	if !strings.HasPrefix(endpoint, "https://") && !isInsecure {
		return fmt.Errorf("endpoint must use HTTPS (got %q); set insecureSkipVerify to allow HTTP", endpoint)
	}

	encoder, err := crypto.NewKeyEncoder("PEM")
	if err != nil {
		return err
	}

	pubPEM, err := encoder.EncodePublic(kp.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to encode public key: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(pubPEM))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-pem-file")
	req.Header.Set("X-Key-ID", kp.KeyID) // Add KeyID header for correlation

	// Configure TLS client if specified
	httpClient := p.client
	if target.TLS != nil {
		// Clone default transport to customize TLS per request
		// [SEC:T-2] If customized transport is needed (e.g. mutual TLS) we must build it here.
		// For MVP, we only support InsecureSkipVerify or system CA unless we load certs dynamically.

		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		if target.TLS.InsecureSkipVerify {
			tlsConfig.InsecureSkipVerify = true
		} else {
			// If CA secret is provided, we would load it here.
			// This requires accessing k8sClient to get the secret.
			// For this iteration, we focus on InsecureSkipVerify support.
			// Full mTLS support is a future improvement.
		}

		transport := &http.Transport{
			TLSClientConfig: tlsConfig,
			// Copy other defaults from http.DefaultTransport if needed
		}

		httpClient = &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request to %s failed: %w", endpoint, err)
	}
	defer resp.Body.Close()

	// [SEC:S-4] Limit response body read to prevent OOM from malicious servers
	const maxResponseBody = 1 << 20 // 1 MB
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody))

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned error: %s", resp.Status)
	}

	return nil
}
