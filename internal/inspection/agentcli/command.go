package agentcli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/inputguard"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/strictjson"
)

func Run(ctx context.Context, args []string, input io.Reader, output io.Writer) error {
	if ctx == nil || output == nil || len(args) != 1 {
		return errors.New("inspection command is invalid")
	}
	switch args[0] {
	case "capabilities":
		return runCapabilities(ctx, input, output)
	case "inspect":
		return runInspect(ctx, input, output)
	case "continue":
		return runContinue(ctx, input, output)
	default:
		return errors.New("inspection command is invalid")
	}
}

func runContinue(ctx context.Context, input io.Reader, output io.Writer) error {
	request, err := readContinueRequest(input)
	if err != nil {
		return err
	}
	config, handled, err := bootstrap("continue", output)
	if err != nil || handled {
		return err
	}
	client, err := newProductClient(config)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(config.ContinueWaitMillis)*time.Millisecond)
	defer cancel()
	var run httpapi.RunView
	if request.RunRef == "" {
		resolution, resolveErr := client.resolveContinuation(ctx)
		if resolveErr != nil || resolution.Status == httpapi.ContinuationNone {
			return writeEnvelope(output, Envelope{
				Schema: SchemaVersion, Command: "continue", State: "unable",
				Message: "当前会话中未找到可继续的巡检。",
			})
		}
		if resolution.Status == httpapi.ContinuationAmbiguous {
			candidates := make([]Candidate, len(resolution.Candidates))
			for index, candidate := range resolution.Candidates {
				candidates[index] = Candidate{RunRef: candidate.RunRef, Area: candidate.Area, Goal: candidate.Goal, StartedAt: candidate.StartedAt}
			}
			return writeEnvelope(output, Envelope{
				Schema: SchemaVersion, Command: "continue", State: "clarification",
				Message: "当前会话中有多个可继续的巡检，请根据区域、目标和开始时间选择。", Candidates: candidates,
			})
		}
		if resolution.Status != httpapi.ContinuationResolved || resolution.Run == nil {
			return errors.New("Product returned an invalid continuation resolution")
		}
		run = *resolution.Run
		request.RunRef = run.RunRef
	} else {
		run, err = client.getRun(ctx, request.RunRef)
		if err != nil {
			return writeEnvelope(output, Envelope{
				Schema: SchemaVersion, Command: "continue", State: "unable",
				Message: "当前会话中未找到可继续的巡检。",
			})
		}
	}
	return presentRun(ctx, client, "continue", run, output)
}

func runCapabilities(ctx context.Context, input io.Reader, output io.Writer) error {
	if err := emptyInput(input); err != nil {
		return err
	}
	config, handled, err := bootstrap("capabilities", output)
	if err != nil || handled {
		return err
	}
	client, err := newProductClient(config)
	if err != nil {
		return err
	}
	set, err := client.queryCapabilities(ctx)
	if err != nil {
		return writeEnvelope(output, Envelope{
			Schema: SchemaVersion, Command: "capabilities", State: "unable",
			Message: "当前无法读取本站点可执行的巡检，请稍后重试或联系本机管理员。",
		})
	}
	offerings := make([]Offering, len(set.Capabilities))
	for index, capability := range set.Capabilities {
		offerings[index] = Offering{
			Title: capability.Title, Description: capability.Description,
			Examples: append([]string(nil), capability.Examples...),
		}
	}
	return writeEnvelope(output, Envelope{
		Schema: SchemaVersion, Command: "capabilities", State: "ready",
		Message: "当前站点可执行以下巡检。", ContextLabel: set.ContextLabel, Offerings: offerings,
	})
}

func runInspect(ctx context.Context, input io.Reader, output io.Writer) error {
	request, err := readStartRequest(input)
	if err != nil {
		return err
	}
	config, handled, err := bootstrap("inspect", output)
	if err != nil || handled {
		return err
	}
	client, err := newProductClient(config)
	if err != nil {
		return err
	}
	key, err := invocationKey()
	if err != nil {
		return err
	}
	run, err := client.requestInspection(ctx, request, key)
	if err != nil {
		var handoff *interactionError
		if errors.As(err, &handoff) {
			return writeEnvelope(output, Envelope{
				Schema: SchemaVersion, Command: "inspect", State: "interaction_required",
				Message: handoff.interaction.Message,
				Interaction: &Interaction{
					Title: handoff.interaction.Title, Message: handoff.interaction.Message,
					ActionLabel: handoff.interaction.ActionLabel, Capability: handoff.interaction.Capability,
					HandoffRef: handoff.interaction.HandoffRef,
				},
			})
		}
		return writeEnvelope(output, Envelope{
			Schema: SchemaVersion, Command: "inspect", State: "unable",
			Message: "本次巡检未能发起，请稍后重试或联系本机管理员。",
		})
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(config.InspectWaitMillis)*time.Millisecond)
	defer cancel()
	return presentRun(ctx, client, "inspect", run, output)
}

// All reads after admission share one wait budget. Cancelling these reads does
// not cancel the Product-owned run or discard the last trusted Run Reference.
func presentRun(ctx context.Context, client *productClient, command string, run httpapi.RunView, output io.Writer) error {
	for run.Status == httpapi.RunAccepted || run.Status == httpapi.RunWorking {
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return writeRunEnvelope(output, command, run, nil)
		case <-timer.C:
		}
		next, err := client.getRun(ctx, run.RunRef)
		if err != nil {
			if ctx.Err() != nil {
				return writeRunEnvelope(output, command, run, nil)
			}
			return writeEnvelope(output, Envelope{
				Schema: SchemaVersion, Command: command, State: "unable",
				Message: "巡检已提交，但当前无法读取进度，请稍后继续查询。", RunRef: run.RunRef,
			})
		}
		run = next
	}
	if run.Status != httpapi.RunReady {
		return writeRunEnvelope(output, command, run, nil)
	}
	result, err := client.getResult(ctx, run.RunRef)
	if err != nil {
		state, message := "unable", "当前无法读取巡检结果，请稍后继续查询。"
		if ctx.Err() != nil {
			state, message = "working", "巡检结果正在准备，请稍后继续查询。"
		}
		return writeEnvelope(output, Envelope{
			Schema: SchemaVersion, Command: command, State: state,
			Message: message, RunRef: run.RunRef,
		})
	}
	projection := textProjection(result)
	return writeRunEnvelope(output, command, run, &projection)
}

func bootstrap(command string, output io.Writer) (clientConfig, bool, error) {
	config, err := loadClientConfig()
	if err != nil {
		return clientConfig{}, false, err
	}
	if err := config.authorizeConversation(os.Getenv("CODEX_THREAD_ID")); err != nil {
		return clientConfig{}, true, writeEnvelope(output, Envelope{
			Schema: SchemaVersion, Command: command, State: "interaction_required",
			Message: "当前 Codex 任务尚未绑定到本站点巡检。",
			Interaction: &Interaction{
				Title: "需要本机巡检绑定", Message: "请在受信任的本机管理界面完成 Codex 任务绑定后重试。",
				ActionLabel: "打开本机管理界面", Capability: "operator.codex_binding",
			},
		})
	}
	return config, false, nil
}

func readStartRequest(input io.Reader) (StartRequest, error) {
	if input == nil {
		return StartRequest{}, errors.New("standard input is unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(input, 64<<10+1))
	if err != nil || len(raw) == 0 || len(raw) > 64<<10 {
		return StartRequest{}, errors.New("inspect input is invalid")
	}
	var request StartRequest
	if !utf8.Valid(raw) || strictjson.ValidateExactFields(raw, &request, 4) != nil || json.Unmarshal(raw, &request) != nil ||
		request.Instruction != strings.TrimSpace(request.Instruction) || len(request.Instruction) == 0 || len(request.Instruction) > 2000 ||
		inputguard.ValidateText(request.Instruction) != nil || len(request.Context) > 16 {
		return StartRequest{}, errors.New("inspect input is invalid")
	}
	contextNames := make(map[string]struct{}, len(request.Context))
	for _, item := range request.Context {
		if item.Name != strings.TrimSpace(item.Name) || len(item.Name) == 0 || len(item.Name) > 128 ||
			item.Value != strings.TrimSpace(item.Value) || len(item.Value) == 0 || len(item.Value) > 512 ||
			inputguard.ValidateText(item.Name) != nil || inputguard.ValidateText(item.Value) != nil {
			return StartRequest{}, errors.New("inspect input is invalid")
		}
		name := strings.ToLower(item.Name)
		if _, duplicate := contextNames[name]; duplicate {
			return StartRequest{}, errors.New("inspect input is invalid")
		}
		contextNames[name] = struct{}{}
	}
	return request, nil
}

func readContinueRequest(input io.Reader) (ContinueRequest, error) {
	if input == nil {
		return ContinueRequest{}, errors.New("standard input is unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(input, 64<<10+1))
	if err != nil || len(raw) == 0 || len(raw) > 64<<10 || !utf8.Valid(raw) {
		return ContinueRequest{}, errors.New("continue input is invalid")
	}
	var request ContinueRequest
	if strictjson.ValidateExactFields(raw, &request, 2) != nil || json.Unmarshal(raw, &request) != nil ||
		request.RunRef != "" && !publicRefPattern.MatchString(request.RunRef) {
		return ContinueRequest{}, errors.New("continue input is invalid")
	}
	return request, nil
}

func invocationKey() (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	key := "codex-" + hex.EncodeToString(random)
	clear(random)
	return key, nil
}

func textProjection(result httpapi.ResultView) TextResult {
	sections := make([]TextSection, len(result.Sections))
	for index, section := range result.Sections {
		sections[index] = TextSection{
			Title: section.Title, Conclusion: section.Conclusion,
			Details: append([]string(nil), section.Details...),
		}
	}
	return TextResult{
		RunRef: result.RunRef, Summary: result.Summary, Answer: result.Answer, Question: result.Question,
		Sections: sections, Limitations: append([]string(nil), result.Limitations...), CompletedAt: result.CompletedAt,
	}
}

func writeRunEnvelope(output io.Writer, command string, run httpapi.RunView, result *TextResult) error {
	return writeEnvelope(output, Envelope{
		Schema: SchemaVersion, Command: command, State: string(run.Status), Message: run.Message,
		RunRef: run.RunRef, Result: result,
	})
}

func writeEnvelope(output io.Writer, envelope Envelope) error {
	raw, err := httpapi.MarshalPublicJSON(envelope)
	if err != nil {
		return err
	}
	_, err = output.Write(append(raw, '\n'))
	return err
}
