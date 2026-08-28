package p3pserver

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"time"
)

func doWithRetry(ctx context.Context, client HTTPDoer, factory func() (*http.Request, error), maxRetries int, initialDelay time.Duration) (*http.Response, error) {
	for attempt := 0; attempt <= maxRetries; attempt++ {
		req, err := factory()
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req.WithContext(ctx))
		if err == nil && !retriableStatus(resp.StatusCode) {
			return resp, nil
		}
		if attempt == maxRetries {
			return resp, err
		}
		delay := initialDelay * time.Duration(1<<attempt)
		if err == nil {
			if seconds, parseErr := strconv.ParseFloat(resp.Header.Get("Retry-After"), 64); parseErr == nil && seconds >= 0 {
				delay = time.Duration(seconds * float64(time.Second))
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, context.Canceled
}
func retriableStatus(status int) bool { return status == http.StatusTooManyRequests || status >= 500 }
