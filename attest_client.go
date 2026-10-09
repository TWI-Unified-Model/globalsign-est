package est

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
)

// InitiateRemoteAttestation performs the first leg of attested credential
// acquisition, obtaining the Freshness kind and, for present-nonce, a Handle
// to be embedded in Evidence. It also reports the credential acquisition
// mechanism the CAS supports for this target.
//
// This is the EST binding of the caapi.v1 InitiateRemoteAttestation RPC.
//
// A client already configured for an absent Freshness kind may complete this
// leg locally and must not call this method.
func (c *Client) InitiateRemoteAttestation(
	ctx context.Context,
	target, credentialType string,
) (*AttestationInitiateResponse, error) {
	endpoint := attestInitiateEndpoint

	q := url.Values{}
	if target != "" {
		q.Set(attestTargetParam, target)
	}
	if credentialType != "" {
		q.Set(attestCredentialTypeParam, credentialType)
	}
	if len(q) > 0 {
		endpoint += "?" + q.Encode()
	}

	req, err := c.newRequest(ctx, http.MethodGet, endpoint, "", "", mimeTypeAttestInitiate, nil)
	if err != nil {
		return nil, err
	}

	httpc, _, err := c.makeHTTPClient()
	if err != nil {
		return nil, err
	}

	resp, err := httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute HTTP request: %w", err)
	}
	defer consumeAndClose(resp.Body)

	if err := checkResponseError(resp); err != nil {
		return nil, err
	}

	if err := verifyMediaType(resp, mimeTypeAttestInitiate); err != nil {
		return nil, err
	}

	var out AttestationInitiateResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("failed to decode attestation initiate response: %w", err)
	}

	return &out, nil
}

// EnrollCredential performs the second leg of Attested Enrollment Mode,
// submitting a CSR together with Evidence bound to that CSR and to the
// Freshness returned by InitiateRemoteAttestation.
//
// This is the EST binding of the caapi.v1 EnrollCredential RPC. The returned
// certificate corresponds to plaintext_credential.
func (c *Client) EnrollCredential(
	ctx context.Context,
	ar *AttestedEnrollmentRequest,
) (*x509.Certificate, error) {
	resp, err := c.postAttest(ctx, attestEnrollEndpoint, mimeTypeAttestEnroll, ar, mimeTypePKCS7)
	if err != nil {
		return nil, err
	}
	defer consumeAndClose(resp.Body)

	if err := verifyResponseType(resp, mimeTypePKCS7, encodingTypeBase64); err != nil {
		return nil, err
	}

	return readCertResponse(resp.Body)
}

// RetrieveCredential performs the second leg of Attested Retrieval Mode. The
// returned bundle is encrypted to CEKpub and can only be opened by the holder
// of CEKpri, so its contents remain opaque to both the EST client and the EST
// server.
//
// This is the EST binding of the caapi.v1 RetrieveCredential RPC. The returned
// bundle corresponds to wrapped_credential.
func (c *Client) RetrieveCredential(
	ctx context.Context,
	ar *AttestedRetrievalRequest,
) (*EncryptedCredentialBundle, error) {
	resp, err := c.postAttest(ctx, attestRetrieveEndpoint, mimeTypeAttestRetrieve, ar, mimeTypeAttestBundle)
	if err != nil {
		return nil, err
	}
	defer consumeAndClose(resp.Body)

	if err := verifyMediaType(resp, mimeTypeAttestBundle); err != nil {
		return nil, err
	}

	var out EncryptedCredentialBundle
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("failed to decode encrypted credential bundle: %w", err)
	}

	return &out, nil
}

// RetrieveCredentialRaw performs the second leg of Attested Retrieval Mode and
// returns the EncryptedCredentialBundle exactly as the server sent it, for an
// Attester that opens the container of the revised EST profile itself.
func (c *Client) RetrieveCredentialRaw(ctx context.Context, ar *AttestedRetrievalRequest) ([]byte, error) {
	resp, err := c.postAttest(ctx, attestRetrieveEndpoint, mimeTypeAttestRetrieve, ar, mimeTypeAttestBundle)
	if err != nil {
		return nil, err
	}
	defer consumeAndClose(resp.Body)

	if err := verifyMediaType(resp, mimeTypeAttestBundle); err != nil {
		return nil, err
	}

	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// postAttest marshals and POSTs a JSON attestation request as contentType,
// returning the response for the caller to decode. The caller must close the
// response body.
func (c *Client) postAttest(
	ctx context.Context,
	endpoint string,
	contentType string,
	payload interface{},
	accepts string,
) (*http.Response, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attestation request: %w", err)
	}

	req, err := c.newRequest(ctx, http.MethodPost, endpoint, contentType, "", accepts, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	httpc, _, err := c.makeHTTPClient()
	if err != nil {
		return nil, err
	}

	resp, err := httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute HTTP request: %w", err)
	}

	if err := checkResponseError(resp); err != nil {
		consumeAndClose(resp.Body)
		return nil, err
	}

	return resp, nil
}

// verifyMediaType returns an error unless the media type of the response is t,
// compared without regard to case and parameters (RFC 9110, Section 8.3.1).
func verifyMediaType(r *http.Response, t string) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get(contentTypeHeader))
	if err != nil {
		return fmt.Errorf("missing or malformed %s header: %w", contentTypeHeader, err)
	}
	if mediaType != t {
		return fmt.Errorf("unexpected %s: %s, not %s", contentTypeHeader, mediaType, t)
	}
	return nil
}
