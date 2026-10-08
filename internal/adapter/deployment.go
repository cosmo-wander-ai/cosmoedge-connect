package adapter

import "context"

// SaveTaskConfigurationContext uses the native task save endpoint. On CosmoEdge
// V1 this persists and enables the binding; callers must verify processing and
// must not retry an ambiguous response or issue a redundant enable write.
func (c *Client) SaveTaskConfigurationContext(ctx context.Context, body map[string]any) error {
	_, err := c.postWriteWithContext(ctx, "/task/saveOrUpdate", body)
	return err
}

func (c *Client) QueryDeploymentSchedulesContext(ctx context.Context) (map[string]any, error) {
	response, err := c.postWithContext(ctx, "/schedule/SelectScheduleInfo", map[string]any{})
	if err != nil {
		return nil, err
	}
	return c.resData(response), nil
}
