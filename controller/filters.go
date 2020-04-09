package controller

import (
	"context"
	"envoy-test-filter/filters"
	ext_authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/gogo/googleapis/google/rpc"
)

func ExecuteFilters(ctx context.Context, req *ext_authz.CheckRequest)  (*ext_authz.CheckResponse, error) {
	swagg, err := readApis()

	if swagg != nil {

	}

	resp , err := filters.ValidateToken(ctx, req)

	//Return if the authentication failed
	if resp.Status.Code != int32(rpc.OK) {
		return resp, nil
	}
	//Continue to next filter

	// Publish metrics
	resp , err = filters.PublishMetrics(ctx, req)

	return resp, err

}