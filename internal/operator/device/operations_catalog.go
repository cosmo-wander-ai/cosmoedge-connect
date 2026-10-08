package device

import (
	"context"
	"errors"
)

// Algorithm is a registered capability, not proof that its model executes.
type Algorithm struct {
	ID         string
	Name       string
	Usage      string
	ConfigType string
}

type AlgorithmReader interface {
	ReadAlgorithms(context.Context) ([]Algorithm, error)
}

func (c *v1Client) ReadAlgorithms(ctx context.Context) ([]Algorithm, error) {
	var result []Algorithm
	seen := map[string]bool{}
	for page := 1; page <= 20; page++ {
		r, err := c.client.QueryAlgorithmPageContext(ctx, page, 100)
		if err != nil {
			return nil, err
		}
		rows, ok := arrayValue(r, "rows", "list")
		if !ok {
			return nil, errors.New("algorithm catalog is unavailable")
		}
		for _, raw := range rows {
			row, ok := raw.(map[string]any)
			if !ok {
				return nil, errors.New("invalid algorithm row")
			}
			id := stringValue(row, "algorithmId", "algorithmCode", "id")
			if id == "" || seen[id] {
				return nil, errors.New("incomplete algorithm catalog")
			}
			seen[id] = true
			result = append(result, Algorithm{ID: id, Name: stringValue(row, "algorithmName", "name"), Usage: stringValue(row, "algorithmUsage"), ConfigType: stringValue(row, "configType")})
		}
		total, known := intValue(r["total"])
		if known && len(result) == total {
			return result, nil
		}
		if len(rows) < 100 && !known {
			return result, nil
		}
		if len(rows) == 0 {
			return nil, errors.New("algorithm catalog ended early")
		}
	}
	return nil, errors.New("algorithm catalog page limit exceeded")
}
