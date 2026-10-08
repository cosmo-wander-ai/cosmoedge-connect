package inspectionfixture

import (
	"context"
	"testing"

	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/planning"
	"github.com/cosmo-wander-ai/cosmoedge-connect/internal/inspection/temporary"
)

func TestClosedInterpreterAcceptsBoundNaturalRequestsAsAuto(t *testing.T) {
	interpreter := closedInterpreter{clipWindowSeconds: 5}
	vocabulary := planning.BusinessVocabulary{
		SourceNames: []string{SourceAlias}, ObservableNames: []string{ObservableName},
	}
	for _, instruction := range []string{
		"帮我查看公共区域的现场状态",
		"帮我看看公共区域的现场状态",
		"帮我查看当前区域的现场状态",
		"帮我看看当前区域的现场状态",
	} {
		instruction := instruction
		t.Run(instruction, func(t *testing.T) {
			interpreted, err := interpreter.Interpret(context.Background(), planning.InterpretationRequest{
				Instruction: instruction, Vocabulary: vocabulary,
			})
			if err != nil {
				t.Fatal(err)
			}
			intent := interpreted.Inspection
			if interpreted.Goal != planning.IntentInspect || intent == nil || intent.Mode != planning.ModeStandard ||
				intent.SourceName != SourceAlias || intent.ObservableName != ObservableName || intent.Preference != planning.PreferAuto ||
				intent.TimeScope.Kind != temporary.TimeScopeCurrent || intent.TimeScope.WindowSeconds != 0 {
				t.Fatalf("natural request interpretation=%+v", interpreted)
			}
		})
	}
}

func TestClosedInterpreterRejectsUnboundNaturalRequests(t *testing.T) {
	interpreter := closedInterpreter{clipWindowSeconds: 5}
	vocabulary := planning.BusinessVocabulary{
		SourceNames: []string{SourceAlias}, ObservableNames: []string{ObservableName},
	}
	for _, instruction := range []string{
		"帮我看看西侧就餐区的现场状态",
		"帮我看看公共区域的现场状态并修改摄像头",
	} {
		if _, err := interpreter.Interpret(context.Background(), planning.InterpretationRequest{
			Instruction: instruction, Vocabulary: vocabulary,
		}); err == nil {
			t.Fatalf("unbound instruction %q was accepted", instruction)
		}
	}
}
