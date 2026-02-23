package shield

import "axiom/pkg/models"

const (
	ShieldReadOnly        = "READ_ONLY"
	ShieldSmallBatch      = "SMALL_BATCH"
	ShieldRequireApproval = "REQUIRE_APPROVAL"
	ShieldDryRun          = "DRY_RUN"
)

func Suggested(t string, params map[string]interface{}) *models.SuggestedShield {
	return &models.SuggestedShield{Type: t, Params: params}
}

func DefaultParams(t string) map[string]interface{} {
	switch t {
	case ShieldSmallBatch:
		return map[string]interface{}{"max": 100}
	case ShieldDryRun:
		return map[string]interface{}{"report": true}
	default:
		return map[string]interface{}{}
	}
}
