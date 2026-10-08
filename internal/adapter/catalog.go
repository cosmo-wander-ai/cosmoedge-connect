package adapter

import "context"

// QueryCameraPage queries paginated camera/channel data.
func (c *Client) QueryCameraPage(pageNum, pageSize int) (map[string]any, error) {
	return c.QueryCameraPageContext(context.Background(), pageNum, pageSize)
}

// QueryCameraPageContext queries paginated camera/channel data using the caller's context.
func (c *Client) QueryCameraPageContext(ctx context.Context, pageNum, pageSize int) (map[string]any, error) {
	resp, err := c.postWithContext(ctx, "/Camera/Page", map[string]any{
		"pageNum":  pageNum,
		"pageSize": pageSize,
	})
	if err != nil {
		return nil, err
	}
	return c.resData(resp), nil
}

// AddCameraSource creates one network video source. Callers own validation and
// redaction of the source URL before this transport boundary.
func (c *Client) AddCameraSource(body map[string]any) (map[string]any, error) {
	return c.AddCameraSourceContext(context.Background(), body)
}

// AddCameraSourceContext creates one network video source using the caller's context.
func (c *Client) AddCameraSourceContext(ctx context.Context, body map[string]any) (map[string]any, error) {
	if body == nil {
		body = map[string]any{}
	}
	resp, err := c.postWriteWithContext(ctx, "/Camera/Add", body)
	if err != nil {
		return nil, err
	}
	return c.resData(resp), nil
}

// QueryAlgorithmPage queries paginated algorithm metadata.
func (c *Client) QueryAlgorithmPage(pageNum, pageSize int) (map[string]any, error) {
	return c.QueryAlgorithmPageContext(context.Background(), pageNum, pageSize)
}

// QueryAlgorithmPageContext queries algorithm metadata using the caller's context.
func (c *Client) QueryAlgorithmPageContext(ctx context.Context, pageNum, pageSize int) (map[string]any, error) {
	resp, err := c.postWithContext(ctx, "/Algorithm/Page", map[string]any{
		"pageNum":  pageNum,
		"pageSize": pageSize,
	})
	if err != nil {
		return nil, err
	}
	return c.resData(resp), nil
}

// QueryAtomicModelPage queries paginated atomic model metadata.
func (c *Client) QueryAtomicModelPage(pageNum, pageSize int) (map[string]any, error) {
	return c.QueryAtomicModelPageContext(context.Background(), pageNum, pageSize)
}

// QueryAtomicModelPageContext queries atomic model metadata using the caller's context.
func (c *Client) QueryAtomicModelPageContext(ctx context.Context, pageNum, pageSize int) (map[string]any, error) {
	resp, err := c.postWithContext(ctx, "/atomic/Model/Page", map[string]any{
		"pageNum":  pageNum,
		"pageSize": pageSize,
	})
	if err != nil {
		return nil, err
	}
	return c.resData(resp), nil
}

// QueryAtomicModelList queries the atomic model list used by algorithm layout.
func (c *Client) QueryAtomicModelList() (map[string]any, error) {
	resp, err := c.post("/atomic/model/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	return c.resData(resp), nil
}

// QueryAlgorithmLayoutList queries AIBox algorithm layout definitions.
func (c *Client) QueryAlgorithmLayoutList() (map[string]any, error) {
	return c.QueryAlgorithmLayoutListContext(context.Background())
}

// QueryAlgorithmLayoutListContext queries layout definitions using the caller's context.
func (c *Client) QueryAlgorithmLayoutListContext(ctx context.Context) (map[string]any, error) {
	resp, err := c.postWithContext(ctx, "/algorithm/layout/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	return c.resData(resp), nil
}

// SaveAlgorithmLayout persists algorithm layout definitions.
func (c *Client) SaveAlgorithmLayout(body map[string]any) (map[string]any, error) {
	return c.SaveAlgorithmLayoutContext(context.Background(), body)
}

// SaveAlgorithmLayoutContext persists algorithm layout definitions using the caller's context.
func (c *Client) SaveAlgorithmLayoutContext(ctx context.Context, body map[string]any) (map[string]any, error) {
	if body == nil {
		body = map[string]any{}
	}
	resp, err := c.postWriteWithContext(ctx, "/algorithm/layout/save", body)
	if err != nil {
		return nil, err
	}
	return c.resData(resp), nil
}

// QueryPassFlowList queries algorithms that can produce passenger flow stats.
func (c *Client) QueryPassFlowList() (map[string]any, error) {
	resp, err := c.post("/Algorithm/PassFlowList", map[string]any{})
	if err != nil {
		return nil, err
	}
	return c.resData(resp), nil
}

// QueryPassengerFlowNumber queries passenger flow statistics.
func (c *Client) QueryPassengerFlowNumber(body map[string]any) (map[string]any, error) {
	if body == nil {
		body = map[string]any{}
	}
	resp, err := c.post("/Event/QueryPassengerFlowNumber", body)
	if err != nil {
		return nil, err
	}
	return c.resData(resp), nil
}

// ExportAlarm triggers an alarm export and returns the generated file URL.
func (c *Client) ExportAlarm(body map[string]any) (map[string]any, error) {
	if body == nil {
		body = map[string]any{}
	}
	resp, err := c.post("/Event/ExportAlarm", body)
	if err != nil {
		return nil, err
	}
	return c.resData(resp), nil
}

// QueryTaskRunningDetail queries task runtime status by task IDs.
func (c *Client) QueryTaskRunningDetail(tasks []string) (map[string]any, error) {
	return c.QueryTaskRunningDetailContext(context.Background(), tasks)
}

// QueryTaskRunningDetailContext queries task runtime status using the caller's context.
func (c *Client) QueryTaskRunningDetailContext(ctx context.Context, tasks []string) (map[string]any, error) {
	if tasks == nil {
		tasks = []string{}
	}
	resp, err := c.postWithContext(ctx, "/Task/RunningDetail", map[string]any{"tasks": tasks})
	if err != nil {
		return nil, err
	}
	return c.resData(resp), nil
}

// SwitchTask starts or stops one configured task.
func (c *Client) SwitchTask(body map[string]any) (map[string]any, error) {
	return c.SwitchTaskContext(context.Background(), body)
}

// SwitchTaskContext starts or stops one configured task using the caller's context.
func (c *Client) SwitchTaskContext(ctx context.Context, body map[string]any) (map[string]any, error) {
	if body == nil {
		body = map[string]any{}
	}
	resp, err := c.postWriteWithContext(ctx, "/Task/SwitchTask", body)
	if err != nil {
		return nil, err
	}
	return c.resData(resp), nil
}

// QueryTaskSwitch queries one configured task's switch state.
func (c *Client) QueryTaskSwitch(body map[string]any) (map[string]any, error) {
	return c.QueryTaskSwitchContext(context.Background(), body)
}

// QueryTaskSwitchContext queries one configured task's switch state using the caller's context.
func (c *Client) QueryTaskSwitchContext(ctx context.Context, body map[string]any) (map[string]any, error) {
	if body == nil {
		body = map[string]any{}
	}
	resp, err := c.postWithContext(ctx, "/Task/QuerySwitch", body)
	if err != nil {
		return nil, err
	}
	return c.resData(resp), nil
}

// QueryTaskParam queries algorithm task parameters bound to a channel.
func (c *Client) QueryTaskParam(channelID, algorithmID string) (map[string]any, error) {
	return c.QueryTaskParamContext(context.Background(), channelID, algorithmID)
}

// QueryTaskParamContext queries algorithm task parameters using the caller's context.
func (c *Client) QueryTaskParamContext(ctx context.Context, channelID, algorithmID string) (map[string]any, error) {
	resp, err := c.postWithContext(ctx, "/Task/QueryParam", map[string]any{
		"channelId":   channelID,
		"algorithmId": algorithmID,
	})
	if err != nil {
		return nil, err
	}
	return c.resData(resp), nil
}

// UpdateTaskParameters changes the parameter document for one configured task.
func (c *Client) UpdateTaskParameters(body map[string]any) (map[string]any, error) {
	return c.UpdateTaskParametersContext(context.Background(), body)
}

// UpdateTaskParametersContext changes task parameters using the caller's context.
func (c *Client) UpdateTaskParametersContext(ctx context.Context, body map[string]any) (map[string]any, error) {
	if body == nil {
		body = map[string]any{}
	}
	resp, err := c.postWriteWithContext(ctx, "/Task/ModifyParam", body)
	if err != nil {
		return nil, err
	}
	return c.resData(resp), nil
}

// QueryTaskConfig queries the persisted task configuration for a channel algorithm pair.
func (c *Client) QueryTaskConfig(channelID, algorithmID string) (map[string]any, error) {
	return c.QueryTaskConfigContext(context.Background(), channelID, algorithmID)
}

// QueryTaskConfigContext queries persisted task configuration using the caller's context.
func (c *Client) QueryTaskConfigContext(ctx context.Context, channelID, algorithmID string) (map[string]any, error) {
	resp, err := c.postWithContext(ctx, "/task/selectConfigByAlgorithmId", map[string]any{
		"channelId":   channelID,
		"algorithmId": algorithmID,
	})
	if err != nil {
		return nil, err
	}
	return c.resData(resp), nil
}
