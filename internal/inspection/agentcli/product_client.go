package agentcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/localstate"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/strictjson"
)

const maximumProductResponseBytes = 64 << 10

var tokenPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type productClient struct {
	endpoint string
	token    string
	client   *http.Client
}

func newProductClient(config clientConfig) (*productClient, error) {
	if err := localstate.ValidateFile(config.TokenFile); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(config.TokenFile)
	if err != nil || len(raw) > 65 {
		return nil, errors.New("inspection channel credential is unavailable")
	}
	token := strings.TrimSpace(string(raw))
	clear(raw)
	if !tokenPattern.MatchString(token) {
		return nil, errors.New("inspection channel credential is invalid")
	}
	return &productClient{
		endpoint: config.Endpoint,
		token:    token,
		client: &http.Client{
			Timeout:       10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (c *productClient) queryCapabilities(ctx context.Context) (capabilitySet, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+"/api/inspection/capabilities", nil)
	if err != nil {
		return capabilitySet{}, err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	response, err := c.client.Do(request)
	if err != nil {
		return capabilitySet{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumProductResponseBytes+1))
		return capabilitySet{}, errors.New("inspection Product rejected the capability query")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximumProductResponseBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumProductResponseBytes {
		return capabilitySet{}, errors.New("inspection Product capability response is invalid")
	}
	var set capabilitySet
	if strictjson.ValidateExactFields(raw, &set, 4) != nil || json.Unmarshal(raw, &set) != nil {
		return capabilitySet{}, errors.New("inspection Product capability response is invalid")
	}
	if httpapi.ValidatePublicResponse(set) != nil || len(set.Capabilities) > 64 {
		return capabilitySet{}, errors.New("inspection Product capability response is invalid")
	}
	for _, capability := range set.Capabilities {
		if len(capability.Examples) == 0 {
			return capabilitySet{}, errors.New("inspection Product capability response is incomplete")
		}
	}
	return set, nil
}

type submissionResponse struct {
	Created bool            `json:"created"`
	Run     httpapi.RunView `json:"run"`
}

type interactionError struct {
	interaction httpapi.InteractionRequired
}

func (e *interactionError) Error() string { return "inspection interaction is required" }

func (c *productClient) requestInspection(ctx context.Context, input StartRequest, key string) (httpapi.RunView, error) {
	body, err := json.Marshal(input)
	if err != nil {
		return httpapi.RunView{}, err
	}
	var response *http.Response
	for attempt := 0; attempt < 2; attempt++ {
		request, requestErr := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/api/inspection/requests", bytes.NewReader(body))
		if requestErr != nil {
			return httpapi.RunView{}, requestErr
		}
		request.Header.Set("Authorization", "Bearer "+c.token)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", key)
		response, err = c.client.Do(request)
		if err == nil {
			break
		}
		if ctx.Err() != nil || attempt == 1 {
			return httpapi.RunView{}, err
		}
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusConflict {
		var handoff struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
			InteractionRequired httpapi.InteractionRequired `json:"interactionRequired"`
		}
		if decodeProductJSON(response.Body, &handoff) == nil && handoff.Error.Code == "interaction_required" &&
			httpapi.ValidatePublicResponse(handoff.InteractionRequired) == nil {
			return httpapi.RunView{}, &interactionError{interaction: handoff.InteractionRequired}
		}
		return httpapi.RunView{}, errors.New("inspection Product returned an invalid interaction")
	}
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumProductResponseBytes+1))
		return httpapi.RunView{}, errors.New("inspection Product rejected the request")
	}
	var submitted submissionResponse
	if err := decodeProductJSON(response.Body, &submitted); err != nil || httpapi.ValidatePublicResponse(submitted.Run) != nil {
		return httpapi.RunView{}, errors.New("inspection Product returned an invalid run")
	}
	return submitted.Run, nil
}

func (c *productClient) getRun(ctx context.Context, runRef string) (httpapi.RunView, error) {
	var run httpapi.RunView
	if err := c.getJSON(ctx, "/api/inspection/runs/"+runRef, &run); err != nil || run.RunRef != runRef || httpapi.ValidatePublicResponse(run) != nil {
		return httpapi.RunView{}, errors.New("inspection Product returned an invalid run")
	}
	return run, nil
}

func (c *productClient) resolveContinuation(ctx context.Context) (httpapi.ContinuationResolution, error) {
	var resolution httpapi.ContinuationResolution
	if err := c.getJSON(ctx, "/api/inspection/continuation", &resolution); err != nil {
		return httpapi.ContinuationResolution{}, err
	}
	if httpapi.ValidatePublicResponse(resolution) != nil {
		return httpapi.ContinuationResolution{}, errors.New("inspection Product continuation response is invalid")
	}
	return resolution, nil
}

func (c *productClient) getResult(ctx context.Context, runRef string) (httpapi.ResultView, error) {
	var result httpapi.ResultView
	if err := c.getJSON(ctx, "/api/inspection/runs/"+runRef+"/result", &result); err != nil || result.RunRef != runRef || httpapi.ValidatePublicResponse(result) != nil {
		return httpapi.ResultView{}, errors.New("inspection Product returned an invalid result")
	}
	return result, nil
}

func (c *productClient) getJSON(ctx context.Context, path string, output any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+path, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumProductResponseBytes+1))
		return errors.New("inspection Product read failed")
	}
	return decodeProductJSON(response.Body, output)
}

func decodeProductJSON(input io.Reader, output any) error {
	raw, err := io.ReadAll(io.LimitReader(input, maximumProductResponseBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maximumProductResponseBytes {
		return errors.New("inspection Product response is invalid")
	}
	if strictjson.ValidateExactFields(raw, output, 8) != nil || json.Unmarshal(raw, output) != nil {
		return errors.New("inspection Product response is invalid")
	}
	return nil
}

func emptyInput(input io.Reader) error {
	if input == nil {
		return errors.New("standard input is unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(input, 2))
	if err != nil || len(raw) != 0 {
		return errors.New("capabilities requires empty standard input")
	}
	return nil
}
