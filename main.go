package main

import (
	"context"
	newjwt "envoy-test-filter/jwt"
	"fmt"
	"github.com/cactus/go-statsd-client/statsd"
	ext_authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type"
	"github.com/gogo/googleapis/google/rpc"
	"github.com/golang/protobuf/jsonpb"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"log"
	"net"
	"os"
	"os/signal"
	"sort"
)

type server struct {
	mode string
}

func main() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt)

	go listen(":8081", &server{mode: "GATEWAY"})

	<-c
}

func listen(address string, serverType *server) {
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	ext_authz.RegisterAuthorizationServer(s, serverType)
	reflection.Register(s)
	fmt.Printf("Starting %q reciver on %q\n", serverType.mode, address)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func (s *server) Check(ctx context.Context, req *ext_authz.CheckRequest) (*ext_authz.CheckResponse, error) {

	fmt.Printf("======================================== %-24s ========================================\n", fmt.Sprintf("%s Start", s.mode))
	defer fmt.Printf("======================================== %-24s ========================================\n\n", fmt.Sprintf("%s End", s.mode))

	m := jsonpb.Marshaler{Indent: "  "}
	js, err := m.MarshalToString(req)

	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(js)
	}
    caCert,_ := newjwt.ReadFile("./artifacts/server.pem")
	fmt.Printf("%+v\n", req.Attributes.Source.Address)
	fmt.Printf("%+v\n", req.Attributes.Destination.Address)

	var keys []string
	h := false
	for k := range req.Attributes.Request.Http.Headers {
		if k == "authorization" {
			//h = true
			//header := req.Attributes.Request.Http.Headers["authorization"]
			h, _, _ = newjwt.HandleJWT(false, caCert,req.Attributes.Request.Http.Headers )
			fmt.Println("JWT header detected" + k)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		fmt.Printf("%+v:%+v\n", k, req.Attributes.Request.Http.Headers[k])
	}

	resp := &ext_authz.CheckResponse{}
	if h {
		resp = &ext_authz.CheckResponse{
			Status: &status.Status{Code: int32(rpc.OK)},
			HttpResponse: &ext_authz.CheckResponse_OkResponse{
				OkResponse: &ext_authz.OkHttpResponse{

				},
			},
		}

	} else {
		resp = &ext_authz.CheckResponse{
			Status: &status.Status{Code: int32(rpc.UNAUTHENTICATED)},
			HttpResponse: &ext_authz.CheckResponse_DeniedResponse{
				DeniedResponse: &ext_authz.DeniedHttpResponse{
					Status:  &envoy_type.HttpStatus{
						Code: envoy_type.StatusCode_Unauthorized,
					},
					Body: "Error occurred while authenticating.",

				},
			},
		}
	}

	config := &statsd.ClientConfig{
		Address: "127.0.0.1:8125",
		Prefix: "test-client",
	}

	client, err := statsd.NewClientWithConfig(config)

	// and handle any initialization errors
	if err != nil {
		log.Fatal(err)
	}

	// make sure to clean up
	defer client.Close()

	// Send a stat
	err = client.Inc("stat1", 42, 1.0)
	// handle any errors
	if err != nil {
		log.Printf("Error sending metric: %+v", err)
	}
	return resp, nil
}
