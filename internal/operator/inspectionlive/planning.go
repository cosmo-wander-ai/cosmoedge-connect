package inspectionlive

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/application"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/httpapi"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/inputguard"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/media"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/mediaprep"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/planning"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/resolver"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
)

type synchronizedPlanner struct {
	sync  *catalogSynchronizer
	inner *planning.Service
}

func (p synchronizedPlanner) QueryCapabilities(ctx context.Context, binding httpapi.SessionBinding) (httpapi.CapabilitySet, error) {
	if err := p.sync.Sync(ctx); err != nil {
		switch {
		case errors.Is(err, ErrConnectionRequired):
			return connectionCapabilities("需要先在本机完成设备接入，接入后即可查看真实现场画面。"), nil
		case errors.Is(err, ErrCameraUnavailable):
			return connectionCapabilities("当前设备尚未发现可用摄像头，请先在本机完成视频源配置。"), nil
		default:
			return httpapi.CapabilitySet{}, err
		}
	}
	return p.inner.QueryCapabilities(ctx, binding)
}

func (p synchronizedPlanner) Plan(ctx context.Context, request application.PlanningRequest) (application.PlanningDecision, error) {
	if err := p.sync.Sync(ctx); err != nil {
		switch {
		case errors.Is(err, ErrConnectionRequired):
			return p.inner.RequireConnection(ctx, request)
		case errors.Is(err, ErrCameraUnavailable):
			return p.inner.RequireConnection(ctx, request)
		default:
			return application.PlanningDecision{}, err
		}
	}
	return p.inner.Plan(ctx, request)
}

func connectionCapabilities(description string) httpapi.CapabilitySet {
	return httpapi.CapabilitySet{
		ContextLabel: "当前现场",
		Capabilities: []httpapi.CapabilityView{{
			CapabilityRef: "cap_local_connection", Title: "现场接入准备",
			Description: description, Examples: []string{"帮我查看当前现场情况"},
		}},
	}
}

type naturalInterpreter struct{}

func (naturalInterpreter) Interpret(_ context.Context, request planning.InterpretationRequest) (planning.InterpretedIntent, error) {
	instruction := strings.TrimSpace(request.Instruction)
	if instruction == "" || !containsHan(instruction) {
		return planning.InterpretedIntent{}, errors.New("现场查看要求需要使用自然中文描述")
	}

	// When an upstream agent (e.g. WorkBuddy) has already parsed the user's
	// request into structured semantic fields, use them directly instead of
	// applying hardcoded keyword matching.
	if request.TemporaryIntent != nil {
		if len(request.Vocabulary.SourceNames) != 1 {
			return planning.InterpretedIntent{}, errors.New("当前现场能力尚未准备完成")
		}
		if inputguard.ValidateText(request.TemporaryIntent.Subject) != nil ||
			inputguard.ValidateText(request.TemporaryIntent.Region) != nil ||
			inputguard.ValidateText(request.TemporaryIntent.Observable) != nil {
			return planning.InterpretedIntent{}, errors.New("临时查看要求包含无法安全处理的内容")
		}
		temporaryIntent := *request.TemporaryIntent
		return planning.InterpretedIntent{Goal: planning.IntentInspect, Inspection: &planning.InspectionIntent{
			Mode: planning.ModeTemporaryVisual, SourceName: request.Vocabulary.SourceNames[0],
			Preference: planning.PreferSnapshot, TimeScope: temporary.TimeScope{Kind: temporary.TimeScopeCurrent},
			Temporary: &temporaryIntent,
		}}, nil
	}

	if containsAny(instruction, "视频片段", "截取视频", "查看回放", "调取回放", "录像") {
		return planning.InterpretedIntent{}, errors.New("当前版本暂不支持视频片段或回放")
	}
	if containsAny(instruction, "接入设备", "连接设备", "配置摄像头", "添加摄像头") {
		purpose := planning.ConnectNew
		return planning.InterpretedIntent{Goal: planning.IntentConnect, Connection: &purpose}, nil
	}
	if !containsAny(instruction, "看", "查看", "检查", "巡检", "现场", "画面", "区域", "情况", "状态") {
		return planning.InterpretedIntent{}, errors.New("这不是可识别的现场查看要求")
	}
	if len(request.Vocabulary.SourceNames) != 1 || !containsString(request.Vocabulary.ObservableNames, ObservableName) {
		return planning.InterpretedIntent{}, errors.New("当前现场能力尚未准备完成")
	}
	if inputguard.ValidateText(instruction) != nil {
		return planning.InterpretedIntent{}, errors.New("现场查看要求包含不能在对话中处理的连接或设备操作信息")
	}
	if !genericSceneRequest(instruction) {
		temporaryIntent, err := temporaryIntentFromInstruction(instruction)
		if err != nil {
			return planning.InterpretedIntent{}, err
		}
		return planning.InterpretedIntent{Goal: planning.IntentInspect, Inspection: &planning.InspectionIntent{
			Mode: planning.ModeTemporaryVisual, SourceName: request.Vocabulary.SourceNames[0],
			Preference: planning.PreferSnapshot, TimeScope: temporary.TimeScope{Kind: temporary.TimeScopeCurrent},
			Temporary: &temporaryIntent,
		}}, nil
	}
	intent := planning.InspectionIntent{
		Mode: planning.ModeStandard, SourceName: request.Vocabulary.SourceNames[0],
		ObservableName: ObservableName, Preference: planning.PreferSnapshot,
		TimeScope: temporary.TimeScope{Kind: temporary.TimeScopeCurrent},
	}
	return planning.InterpretedIntent{Goal: planning.IntentInspect, Inspection: &intent}, nil
}

// genericSceneRequest keeps only genuinely generic status questions on the
// published standard template. Any remaining business noun or criterion is a
// one-shot visual question and must not be collapsed into the fixed generic
// standard prompt.
func genericSceneRequest(instruction string) bool {
	instruction = stripAttachmentDeliverySuffix(instruction)
	remaining := strings.Join(strings.Fields(instruction), "")
	replacer := strings.NewReplacer(
		"帮我", "", "麻烦", "", "请", "", "看一下", "", "看下", "", "看看", "", "查看", "", "检查", "", "巡检", "",
		"公共区域", "", "当前区域", "", "这个区域", "", "该区域", "", "就餐区", "", "用餐区", "", "现场", "", "画面", "", "区域", "",
		"当前", "", "现在", "", "此刻", "", "实时", "", "是什么情况", "", "什么情况", "", "怎么样", "", "如何", "", "情况", "", "状态", "",
		"的", "", "一下", "", "？", "", "?", "", "。", "", "，", "", ",", "", "！", "", "!", "", " ", "",
	)
	return replacer.Replace(remaining) == ""
}

func temporaryIntentFromInstruction(instruction string) (planning.TemporaryObservationIntent, error) {
	region := temporaryRegion(instruction)
	subject := temporarySubject(instruction)
	observable := temporaryObservable(instruction, region)
	if utf8.RuneCountInString(observable) > 240 {
		return planning.TemporaryObservationIntent{}, errors.New("临时查看要求过长，请只描述一个需要观察的问题")
	}
	spec, err := temporary.NewSpec(temporary.Intent{
		Subject: subject, Region: region, Observable: observable, Locale: "zh-CN",
		TimeScope: temporary.TimeScope{Kind: temporary.TimeScopeCurrent}, EvidenceTTLSeconds: 10 * 60,
	})
	if err != nil {
		return planning.TemporaryObservationIntent{}, errors.New("临时查看要求包含无法安全处理的内容")
	}
	return planning.TemporaryObservationIntent{
		Subject: spec.Subject, Region: spec.Region, Observable: spec.Observable,
		Locale: spec.Locale, EvidenceTTLSeconds: spec.EvidenceTTLSeconds,
	}, nil
}

func temporaryRegion(instruction string) string {
	for _, region := range []string{
		"东侧就餐区", "西侧就餐区", "东侧用餐区", "西侧用餐区", "公共区域", "当前区域", "这个区域", "该区域",
		"就餐区", "用餐区", "后厨", "厨房", "收银台", "入口", "大厅", "走廊", "仓库", "货架区",
	} {
		if strings.Contains(instruction, region) {
			return region
		}
	}
	return "当前区域"
}

func temporarySubject(instruction string) string {
	for _, candidate := range []struct {
		name    string
		markers []string
	}{
		{name: "桌椅", markers: []string{"桌椅", "桌子", "椅子", "桌面", "摆放"}},
		{name: "地面", markers: []string{"地面", "积水", "水渍"}},
		{name: "环境卫生", markers: []string{"卫生", "清洁", "垃圾", "污渍", "残留"}},
		{name: "人员和客流", markers: []string{"人员", "人数", "客流", "拥堵", "拥挤", "排队"}},
		{name: "现场安全", markers: []string{"烟雾", "火焰", "消防", "通道", "安全"}},
		{name: "货架陈列", markers: []string{"货架", "陈列", "商品摆放"}},
	} {
		if containsAny(instruction, candidate.markers...) {
			return candidate.name
		}
	}
	return "现场情况"
}

func temporaryObservable(instruction, region string) string {
	value := strings.Join(strings.Fields(stripAttachmentDeliverySuffix(instruction)), " ")
	for {
		trimmed := value
		for _, prefix := range []string{"麻烦帮我", "请帮我", "帮我", "麻烦", "请", "看一下", "看下", "看看", "查看", "检查", "巡检"} {
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, prefix))
		}
		if trimmed == value {
			break
		}
		value = trimmed
	}
	value = strings.TrimSpace(strings.TrimPrefix(value, region))
	value = strings.TrimSpace(strings.TrimPrefix(value, "的"))
	// Temporary observations describe visible facts. A request phrased as a
	// compliance verdict is narrowed to visible state and obvious deviation;
	// the fixed prompt still forbids any compliance conclusion.
	for _, phrase := range []string{"是否符合标准", "是否符合要求", "是否达标", "达不达标", "是否合规", "合不合规"} {
		value = strings.ReplaceAll(value, phrase, "的可见状态及明显偏差")
	}
	value = strings.TrimSpace(value)
	if value == "" || genericSceneRequest(value) {
		return "当前画面中的可见情况"
	}
	return value
}

// stripAttachmentDeliverySuffix removes only a trailing request to return the
// snapshot. Delivery is already part of every inspection result and must not
// become part of the visual question. Matching only at the tail preserves
// legitimate subjects such as "墙上图片是否歪斜".
func stripAttachmentDeliverySuffix(instruction string) string {
	value := strings.TrimSpace(instruction)
	value = strings.TrimRight(value, " \t\r\n，,。；;！？!?")
	for _, suffix := range []string{
		"把现场图片发回来", "把现场快照发回来", "把现场截图发回来",
		"把图片发回来", "把快照发回来", "把截图发回来",
		"返回现场图片", "返回现场快照", "返回现场截图",
		"返回图片", "返回快照", "返回截图",
		"发回现场图片", "发回现场快照", "发回现场截图",
		"发回图片", "发回快照", "发回截图",
		"附上现场图片", "附上现场快照", "附上现场截图",
		"附上图片", "附上快照", "附上截图",
	} {
		if !strings.HasSuffix(value, suffix) {
			continue
		}
		value = strings.TrimSpace(strings.TrimSuffix(value, suffix))
		for {
			previous := value
			value = strings.TrimRight(value, " \t\r\n，,。；;！？!?")
			for _, connector := range []string{"同时", "另外", "顺便", "并且", "并", "请"} {
				value = strings.TrimSpace(strings.TrimSuffix(value, connector))
			}
			if value == previous {
				break
			}
		}
		return strings.TrimSpace(value)
	}
	return value
}

func containsHan(value string) bool {
	for _, character := range value {
		if unicode.Is(unicode.Han, character) {
			return true
		}
	}
	return false
}

func containsAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

type liveAuthorities struct{ sync *catalogSynchronizer }

func (a liveAuthorities) AvailableAuthorities(_ context.Context, scope resolver.AuthenticatedScope) ([]resolver.AuthorityAvailability, error) {
	if a.sync == nil || scope.TenantID != TenantID || scope.SiteID != SiteID || scope.PrincipalSHA256 != sessionBinding().PrincipalSHA256 {
		return nil, errors.New("当前现场授权范围不匹配")
	}
	a.sync.mu.Lock()
	verifiedAt := a.sync.verifiedAt
	a.sync.mu.Unlock()
	if verifiedAt.IsZero() || time.Since(verifiedAt) > 2*time.Minute {
		return nil, ErrConnectionRequired
	}
	expiresAt := verifiedAt.Add(3 * time.Minute)
	result := make([]resolver.AuthorityAvailability, 0, 2)
	for _, class := range []resolver.AuthorityClass{resolver.AuthorityDeviceRead, resolver.AuthorityInspectionExecution} {
		result = append(result, resolver.AuthorityAvailability{
			Class: class, TenantID: TenantID, SiteID: SiteID, PrincipalSHA256: scope.PrincipalSHA256,
			SourceHandles: []string{SourceHandle}, VerifiedAt: verifiedAt, ExpiresAt: expiresAt,
		})
	}
	return result, nil
}

type liveTemporaryCompiler struct{}

func (liveTemporaryCompiler) Compile(ctx context.Context, input planning.TemporaryMediaCompilation) (mediaprep.FrozenRequest, error) {
	if err := ctx.Err(); err != nil {
		return mediaprep.FrozenRequest{}, err
	}
	if input.Spec.Validate() != nil || input.TenantID != TenantID || input.SiteID != SiteID ||
		input.SourceRef != SourceHandle || input.CapabilityRef != snapshotCapability ||
		input.RequestedAt.IsZero() || input.EvidenceExpiresAt.IsZero() {
		return mediaprep.FrozenRequest{}, errors.New("临时现场画面请求与当前设备绑定不匹配")
	}
	requestedAt := input.RequestedAt.UTC()
	frozen := mediaprep.FrozenRequest{
		Schema: mediaprep.RequestSchema, TenantID: input.TenantID, SiteID: input.SiteID,
		RequestID: input.RequestID, SourceRef: input.SourceRef, CapabilityRef: input.CapabilityRef,
		TimeScope:          mediaprep.TimeScope{WindowStart: requestedAt, WindowEnd: requestedAt, SampleOrdinal: 0},
		AudienceBindingRef: input.AudienceBindingRef, AudienceSHA256: input.AudienceSHA256,
		EvidenceExpiresAt: input.EvidenceExpiresAt.UTC(),
		Media: mediaprep.MediaSpec{
			Kind: media.KindImage, RunID: input.RuntimeRunID, StepID: input.RuntimeStepID, Attempt: 1,
			PrivacyClass: "internal", RetentionPolicyRef: "live-temporary-observation",
		},
	}
	if err := frozen.Validate(); err != nil {
		return mediaprep.FrozenRequest{}, errors.New("临时现场画面请求无法冻结")
	}
	return frozen, nil
}

var (
	_ application.CapabilityQuery            = synchronizedPlanner{}
	_ application.RequestPlanner             = synchronizedPlanner{}
	_ planning.IntentInterpreter             = naturalInterpreter{}
	_ planning.AuthorityProvider             = liveAuthorities{}
	_ planning.TemporaryMediaRequestCompiler = liveTemporaryCompiler{}
)
