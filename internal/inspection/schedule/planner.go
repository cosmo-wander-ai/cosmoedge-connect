package schedule

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
	_ "time/tzdata"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection"
)

const catchUpSearchDays = 15

type Planner struct {
	clock    Clock
	zones    ZoneLoader
	verifier GrantVerifier
}

func NewPlanner(clock Clock, zones ZoneLoader, verifier GrantVerifier) Planner {
	if clock == nil {
		clock = SystemClock{}
	}
	if zones == nil {
		zones = SystemZoneLoader{}
	}
	return Planner{clock: clock, zones: zones, verifier: verifier}
}

// DueNow uses the injected clock. after is exclusive and the current clock
// value is inclusive.
func (p Planner) DueNow(s Schedule, after time.Time) ([]Occurrence, error) {
	return p.Due(s, after, p.clock.Now())
}

// Due returns timing occurrences in (after, now]. It never connects to a site,
// checks a foreground session, or creates an inspection run.
func (p Planner) Due(s Schedule, after, now time.Time) ([]Occurrence, error) {
	if p.zones == nil {
		return nil, errors.New("inspection schedule planner zone loader is required")
	}
	if err := s.ValidateWithZones(p.zones); err != nil {
		return nil, err
	}
	if now.IsZero() {
		return nil, errors.New("inspection schedule due time is required")
	}
	if s.State != StateActive {
		return nil, nil
	}
	if p.verifier == nil {
		return nil, errors.New("inspection schedule planner authority verifier is required")
	}

	start := effectiveStart(s)
	end := effectiveEnd(s)
	now = now.UTC()
	if now.Before(start) || !now.Before(end) {
		return nil, nil
	}
	scope := scopeForUnchecked(s)
	if err := verifyServiceGrant(p.verifier, s.ServiceGrant, scope, now); err != nil {
		return nil, err
	}
	if after.IsZero() {
		after = start.Add(-time.Nanosecond)
	} else {
		after = after.UTC()
	}
	if after.After(now) {
		return nil, errors.New("inspection schedule due window moved backwards")
	}
	if after.Equal(now) {
		return nil, nil
	}

	location, err := p.zones.LoadLocation(s.Timezone)
	if err != nil {
		return nil, fmt.Errorf("load inspection schedule timezone: %w", err)
	}
	hour, minute, err := parseLocalTime(s.LocalTime)
	if err != nil {
		return nil, err
	}

	lower := after
	switch s.Misfire {
	case MisfireSkip:
		graceStart := now.Add(-time.Duration(s.MisfireGraceSeconds) * time.Second)
		if graceStart.After(lower) {
			lower = graceStart
		}
	case MisfireCatchUpOnce:
		searchStart := now.Add(-catchUpSearchDays * 24 * time.Hour)
		if searchStart.After(lower) {
			lower = searchStart
		}
	default:
		return nil, errors.New("inspection schedule misfire policy is invalid")
	}
	nominalLower := lower.Add(-time.Duration(s.JitterPolicySeconds) * time.Second)
	if nominalLower.Before(start) {
		nominalLower = start
	}

	firstDate := civilDateFrom(nominalLower.In(location))
	lastDate := civilDateFrom(now.In(location))
	occurrences := make([]Occurrence, 0, 2)
	seen := map[string]struct{}{}
	for date, days := firstDate, 0; !date.After(lastDate); date, days = date.Next(), days+1 {
		if days > catchUpSearchDays+3 {
			return nil, errors.New("inspection schedule due window exceeded its bounded civil-date search")
		}
		if !containsWeekday(s.Weekdays, date.Weekday()) {
			continue
		}
		scheduledAt, ok := resolveLocalOnce(location, date, hour, minute)
		if !ok {
			// The civil time did not exist, for example 02:30 during a DST
			// spring-forward transition. It is intentionally skipped.
			continue
		}
		scheduledAt = scheduledAt.UTC()
		if scheduledAt.Before(start) || !scheduledAt.Before(end) {
			continue
		}
		jitter := deterministicJitter(s, scheduledAt)
		dueAt := scheduledAt.Add(jitter)
		if dueAt.Before(start) || !dueAt.Before(end) || !dueAt.After(after) || dueAt.After(now) {
			continue
		}
		if !dueAt.Add(time.Duration(s.RunSpec.RunTTLSeconds) * time.Second).Before(end) {
			continue
		}
		if s.Misfire == MisfireSkip && now.Sub(dueAt) > time.Duration(s.MisfireGraceSeconds)*time.Second {
			continue
		}
		occurrence, err := newOccurrence(s, date, scheduledAt, dueAt, now)
		if err != nil {
			return nil, err
		}
		if _, duplicated := seen[occurrence.IdempotencyKey]; duplicated {
			continue
		}
		seen[occurrence.IdempotencyKey] = struct{}{}
		occurrences = append(occurrences, occurrence)
	}

	sort.Slice(occurrences, func(i, j int) bool {
		if occurrences[i].DueAt.Equal(occurrences[j].DueAt) {
			return occurrences[i].IdempotencyKey < occurrences[j].IdempotencyKey
		}
		return occurrences[i].DueAt.Before(occurrences[j].DueAt)
	})
	if s.Misfire == MisfireCatchUpOnce && len(occurrences) > 1 {
		return occurrences[len(occurrences)-1:], nil
	}
	return occurrences, nil
}

func newOccurrence(s Schedule, date civilDate, scheduledAt, dueAt, generatedAt time.Time) (Occurrence, error) {
	digest := occurrenceDigest(s.TenantID, s.SiteID, s.ScheduleID, s.Revision, scheduledAt)
	grace := time.Duration(s.MisfireGraceSeconds) * time.Second
	occurrence := Occurrence{
		Schema: OccurrenceSchemaVersion, OccurrenceID: "occ_" + digest,
		IdempotencyKey: "occurrence_" + digest, OperationRef: "submit_" + digest,
		RequestID: "occ_" + digest, TenantID: s.TenantID, SiteID: s.SiteID,
		ScheduleID: s.ScheduleID, ScheduleRevision: s.Revision,
		Origin: s.Origin, RunSpec: cloneFrozenRunSpec(s.RunSpec), RunSpecSHA256: s.RunSpecSHA256,
		Delivery: s.Delivery, DeliverySHA256: s.DeliverySHA256,
		ServicePrincipalSHA256: s.ServicePrincipalSHA256, AuthorityScope: scopeForUnchecked(s), ScheduleScopeSHA256: s.ScheduleScopeSHA256,
		AuthoritySHA256: s.AuthoritySHA256,
		Timezone:        s.Timezone, LocalDate: date.String(), LocalTime: s.LocalTime,
		ScheduledAt: scheduledAt.UTC(), DueAt: dueAt.UTC(),
		Deadline: dueAt.UTC().Add(time.Duration(s.RunSpec.RunTTLSeconds) * time.Second), GeneratedAt: generatedAt.UTC(),
		JitterPolicySeconds: s.JitterPolicySeconds, JitterOffsetSeconds: int(dueAt.Sub(scheduledAt) / time.Second), Misfire: s.Misfire,
		MisfireGraceSeconds: s.MisfireGraceSeconds,
		Misfired:            generatedAt.Sub(dueAt) > grace, Concurrency: s.Concurrency,
	}
	occurrence.RequestKey = inspection.RequestKey(occurrence.TenantID, inspection.OriginSchedule, occurrence.RequestID)
	request := occurrence.CreateRunRequest()
	requestSHA, err := canonicalDigest(request)
	if err != nil {
		return Occurrence{}, err
	}
	plan, err := inspection.CompilePlan(occurrence.RunSpec.Template, occurrence.RunSpec.Assignment, request)
	if err != nil {
		return Occurrence{}, fmt.Errorf("compile scheduled inspection occurrence: %w", err)
	}
	if pipelineSHAForPlan(plan) != occurrence.RunSpec.Pipeline.SHA256 {
		return Occurrence{}, errors.New("scheduled inspection pipeline differs from frozen run spec")
	}
	occurrence.RequestSHA256, occurrence.PlanSHA256 = requestSHA, plan.PlanSHA256
	occurrence.SHA256, err = occurrenceSelfDigest(occurrence)
	if err != nil {
		return Occurrence{}, err
	}
	return occurrence, nil
}

func occurrenceDigest(tenantID, siteID, scheduleID string, revision uint64, scheduledAt time.Time) string {
	// A JSON struct gives unambiguous field boundaries. These are the only
	// idempotency inputs by contract.
	payload, _ := json.Marshal(struct {
		Schema      string `json:"schema"`
		TenantID    string `json:"tenantId"`
		SiteID      string `json:"siteId"`
		ScheduleID  string `json:"scheduleId"`
		Revision    uint64 `json:"revision"`
		ScheduledAt string `json:"scheduledAt"`
	}{
		Schema: "cosmoedge.inspection.occurrence-key.v4", TenantID: tenantID, SiteID: siteID,
		ScheduleID: scheduleID, Revision: revision,
		ScheduledAt: scheduledAt.UTC().Format(time.RFC3339Nano),
	})
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

// deterministicJitter delays, but never advances, the nominal local time. The
// same immutable occurrence identity always receives the same offset.
func deterministicJitter(s Schedule, scheduledAt time.Time) time.Duration {
	if s.JitterPolicySeconds == 0 {
		return 0
	}
	key := occurrenceDigest(s.TenantID, s.SiteID, s.ScheduleID, s.Revision, scheduledAt)
	digest := sha256.Sum256([]byte("cosmoedge.inspection.jitter.v3:" + key))
	value := binary.BigEndian.Uint64(digest[:8])
	seconds := value % uint64(s.JitterPolicySeconds+1)
	return time.Duration(seconds) * time.Second
}

type civilDate struct {
	year  int
	month time.Month
	day   int
}

func civilDateFrom(value time.Time) civilDate {
	year, month, day := value.Date()
	return civilDate{year: year, month: month, day: day}
}

func (d civilDate) Next() civilDate {
	next := time.Date(d.year, d.month, d.day, 12, 0, 0, 0, time.UTC).AddDate(0, 0, 1)
	return civilDateFrom(next)
}

func (d civilDate) After(other civilDate) bool {
	return d.ordinal().After(other.ordinal())
}

func (d civilDate) Weekday() time.Weekday {
	return d.ordinal().Weekday()
}

func (d civilDate) String() string {
	return fmt.Sprintf("%04d-%02d-%02d", d.year, int(d.month), d.day)
}

func (d civilDate) ordinal() time.Time {
	return time.Date(d.year, d.month, d.day, 12, 0, 0, 0, time.UTC)
}

// resolveLocalOnce maps one civil time to an instant. A nonexistent civil time
// returns false. When a fall-back transition makes the time ambiguous, the
// earliest instant is selected, so the local schedule fires exactly once.
func resolveLocalOnce(location *time.Location, date civilDate, hour, minute int) (time.Time, bool) {
	naiveUTC := time.Date(date.year, date.month, date.day, hour, minute, 0, 0, time.UTC)
	offsets := map[int]struct{}{}
	for sample := naiveUTC.Add(-72 * time.Hour); !sample.After(naiveUTC.Add(72 * time.Hour)); sample = sample.Add(30 * time.Minute) {
		_, offset := sample.In(location).Zone()
		offsets[offset] = struct{}{}
	}

	candidates := make([]time.Time, 0, 2)
	seen := map[int64]struct{}{}
	for offset := range offsets {
		candidate := naiveUTC.Add(-time.Duration(offset) * time.Second)
		local := candidate.In(location)
		year, month, day := local.Date()
		if year != date.year || month != date.month || day != date.day ||
			local.Hour() != hour || local.Minute() != minute || local.Second() != 0 || local.Nanosecond() != 0 {
			continue
		}
		if _, duplicated := seen[candidate.UnixNano()]; duplicated {
			continue
		}
		seen[candidate.UnixNano()] = struct{}{}
		candidates = append(candidates, candidate.UTC())
	}
	if len(candidates) == 0 {
		return time.Time{}, false
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Before(candidates[j]) })
	return candidates[0], true
}
