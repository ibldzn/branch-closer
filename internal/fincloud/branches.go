package fincloud

import (
	"context"
	"net/url"
	"strings"
)

type Branch struct {
	ID   string
	Name string
}

func (c *Client) GetUnclosedBranches(ctx context.Context) ([]Branch, error) {
	req, err := c.NewRequestWithSessionID(ctx, "GET", "/system/kantor/tutup/kantor", nil)
	if err != nil {
		return nil, err
	}

	var respData struct {
		Data struct {
			Result []struct {
				Locationid   string `json:"locationid"`
				Locationname string `json:"locationname"`
			} `json:"result"`
		} `json:"data"`
		Status string `json:"status"`
	}

	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if err := DecodeJSON(resp, &respData); err != nil {
		return nil, err
	}

	branches := make([]Branch, 0, len(respData.Data.Result))
	for _, b := range respData.Data.Result {
		branches = append(branches, Branch{
			ID:   b.Locationid,
			Name: b.Locationname,
		})
	}

	return branches, nil
}

func (c *Client) CloseBranch(ctx context.Context, branchID, branchName string) error {
	form := url.Values{}
	form.Set("lokasi[0][locationid]", branchID)
	form.Set("lokasi[0][locationname]", branchName)
	form.Set("lokasi[0][akses]", "true")

	encoded := form.Encode()

	req, err := c.NewRequestWithSessionID(ctx, "POST", "/system/kantor/tutup/kantor", strings.NewReader(encoded))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var respData struct {
		Data struct {
			Result []string `json:"result"`
		}
		Error  map[string]any `json:"error"`
		Status string         `json:"status"`
	}

	if err := DecodeJSON(resp, &respData); err != nil {
		return err
	}

	if respData.Status != "ok" {
		return &APIError{
			Message: "failed to close branch",
			Detail:  respData.Error,
		}
	}

	return nil
}

type APIError struct {
	Message string
	Detail  map[string]any
}

func (e *APIError) Error() string {
	return e.Message
}
