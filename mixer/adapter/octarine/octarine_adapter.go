// nolint:lll
// Generates the octarine adapter's resource yaml. It contains the adapter's configuration, name,
// supported template names (metric in this case), and whether it is session or no-session based.
//go:generate $GOPATH/src/istio.io/istio/bin/mixer_codegen.sh -a mixer/adapter/octarine/config/config.proto -x "-s=false -n octarine -t logentry -t authorization"

package octarineadapter

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/golang/glog"

	"github.com/gogo/googleapis/google/rpc"
	"golang.octarinesec.com/liboctarine"
	"google.golang.org/grpc"

	"istio.io/api/mixer/adapter/model/v1beta1"
	"istio.io/istio/mixer/adapter/octarine/config"
	"istio.io/istio/mixer/template/authorization"
	"istio.io/istio/mixer/template/logentry"
)

type (
	// Server is basic server interface
	Server interface {
		Addr() string
		Close() error
		Run(shutdown chan error)
	}

	// OctarineAdapter supports logentry and authorization templates
	OctarineAdapter struct {
		listener net.Listener
		server   *grpc.Server
		octarine liboctarine.LibOctarine
	}
)

var _ logentry.HandleLogEntryServiceServer = &OctarineAdapter{}
var _ authorization.HandleAuthorizationServiceServer = &OctarineAdapter{}

// HandleLogEntry reports activity to the Octarine control plane
func (s *OctarineAdapter) HandleLogEntry(ctx context.Context, request *logentry.HandleLogEntryRequest) (*v1beta1.ReportResult, error) {
	glog.Infof("received request %v\n", *request)
	cfg := &config.Params{}

	if request.AdapterConfig != nil {
		if err := cfg.Unmarshal(request.AdapterConfig.Value); err != nil {
			glog.Errorf("error unmarshalling adapter config: %v", err)
			return nil, err
		}
	}

	for _, instance := range request.Instances {
		fmt.Printf("instance variables: %+v\n", instance.Variables)

		sourceSocket := liboctarine.ExternalSocketInfo{
			// Address: instance.Variables["sourceIp"].GetIpAddressValue().String(),
			Address: "0.0.0.0",
		}

		destinationSocket := liboctarine.ExternalSocketInfo{
			// Address: instance.Variables["destinationIp"].GetIpAddressValue().String(),
			Address: "0.0.0.0",
			Port:    int(instance.Variables["destinationPort"].GetInt64Value()),
		}

		sourceService := fmt.Sprintf("%s:%s@%s",
			instance.Variables["sourceWorkloadNamespace"].GetStringValue(),
			instance.Variables["sourceWorkloadName"].GetStringValue(),
			cfg.Deployment,
		)

		destinationService := fmt.Sprintf("%s:%s@%s",
			instance.Variables["destinationWorkloadNamespace"].GetStringValue(),
			instance.Variables["destinationWorkloadName"].GetStringValue(),
			cfg.Deployment,
		)

		// If the response duration is 0, we're most likely outbound
		// zeroDuration, _ := time.ParseDuration("0ms")
		// requestDuration := instance.Variables["responseDuration"].GetDurationValue()
		outbound := true

		var request liboctarine.ExternalRequest
		var isIncoming int

		if outbound {
			isIncoming = 2
			request = liboctarine.ExternalRequest{
				Protocol:         instance.Variables["protocol"].GetStringValue(),
				MessageID:        0,
				RemoteMessageID:  0,
				LocalSocketInfo:  sourceSocket,
				LocalInstanceID:  instance.Variables["sourceUid"].GetStringValue(),
				LocalServiceID:   sourceService,
				LocalVersion:     instance.Variables["sourceVersion"].GetStringValue(),
				RemoteSocketInfo: destinationSocket,
				RemoteInstanceID: instance.Variables["destinationUid"].GetStringValue(),
				RemoteServiceID:  destinationService,
				RemoteVersion:    instance.Variables["destinationVersion"].GetStringValue(),
				Endpoint:         fmt.Sprintf("path:%s", instance.Variables["endpoint"].GetStringValue()),
				Method:           instance.Variables["method"].GetStringValue(),
			}
		} else {
			isIncoming = 1
			request = liboctarine.ExternalRequest{
				Protocol:         instance.Variables["protocol"].GetStringValue(),
				MessageID:        0,
				RemoteMessageID:  0,
				LocalSocketInfo:  destinationSocket,
				LocalInstanceID:  instance.Variables["destinationUid"].GetStringValue(),
				LocalServiceID:   destinationService,
				LocalVersion:     instance.Variables["destinationVersion"].GetStringValue(),
				RemoteSocketInfo: sourceSocket,
				RemoteInstanceID: instance.Variables["sourceUid"].GetStringValue(),
				RemoteServiceID:  sourceService,
				RemoteVersion:    instance.Variables["sourceVersion"].GetStringValue(),
				Endpoint:         fmt.Sprintf("path:%s", instance.Variables["endpoint"].GetStringValue()),
				Method:           instance.Variables["method"].GetStringValue(),
			}
		}

		code := s.octarine.HandleP2PRequest(true, liboctarine.CheckAndLog, isIncoming, request)
		glog.Infof("Result from liboctarine: %d", code)
	}
	return nil, nil
}

// HandleAuthorization reports activity to the Octarine control plane
func (s *OctarineAdapter) HandleAuthorization(ctx context.Context, authRequest *authorization.HandleAuthorizationRequest) (*v1beta1.CheckResult, error) {
	glog.Infof("received request %v\n", *authRequest)
	cfg := &config.Params{}

	if authRequest.AdapterConfig != nil {
		if err := cfg.Unmarshal(authRequest.AdapterConfig.Value); err != nil {
			glog.Errorf("error unmarshalling adapter config: %v", err)
			return nil, err
		}
	}

	instance := authRequest.Instance

	sourceSocket := liboctarine.ExternalSocketInfo{
		// Address: instance.Variables["sourceIp"].GetIpAddressValue().String(),
		Address: "0.0.0.0",
	}

	destinationSocket := liboctarine.ExternalSocketInfo{
		// Address: instance.Variables["destinationIp"].GetIpAddressValue().String(),
		Address: "0.0.0.0",
		Port:    int(instance.Action.Properties["destinationPort"].GetInt64Value()),
	}

	sourceService := fmt.Sprintf("%s:%s@%s",
		instance.Subject.Properties["sourceWorkloadNamespace"].GetStringValue(),
		instance.Subject.Properties["sourceWorkloadName"].GetStringValue(),
		cfg.Deployment,
	)

	destinationService := fmt.Sprintf("%s:%s@%s",
		instance.Action.Properties["destinationWorkloadNamespace"].GetStringValue(),
		instance.Action.Properties["destinationWorkloadName"].GetStringValue(),
		cfg.Deployment,
	)

	var outbound bool
	// If the destination UID is empty, this is egress traffic which means it's outbound.
	if instance.Action.Properties["destinationUid"].GetStringValue() == "" {
		outbound = true
	} else {
		outbound = false
	}

	var request liboctarine.ExternalRequest
	var isIncoming int

	if outbound {
		isIncoming = 2
		request = liboctarine.ExternalRequest{
			Protocol:         instance.Action.Properties["protocol"].GetStringValue(),
			MessageID:        0,
			RemoteMessageID:  0,
			LocalSocketInfo:  sourceSocket,
			LocalInstanceID:  instance.Subject.Properties["sourceUid"].GetStringValue(),
			LocalServiceID:   sourceService,
			LocalVersion:     instance.Subject.Properties["sourceVersion"].GetStringValue(),
			RemoteSocketInfo: destinationSocket,
			RemoteInstanceID: instance.Action.Properties["destinationUid"].GetStringValue(),
			RemoteServiceID:  destinationService,
			RemoteVersion:    instance.Action.Properties["destinationVersion"].GetStringValue(),
			Endpoint:         fmt.Sprintf("path:%s", instance.Action.Path),
			Method:           instance.Action.Method,
		}
	} else {
		isIncoming = 1
		request = liboctarine.ExternalRequest{
			Protocol:         instance.Action.Properties["protocol"].GetStringValue(),
			MessageID:        0,
			RemoteMessageID:  0,
			LocalSocketInfo:  destinationSocket,
			LocalInstanceID:  instance.Action.Properties["destinationUid"].GetStringValue(),
			LocalServiceID:   destinationService,
			LocalVersion:     instance.Action.Properties["destinationVersion"].GetStringValue(),
			RemoteSocketInfo: sourceSocket,
			RemoteInstanceID: instance.Subject.Properties["sourceUid"].GetStringValue(),
			RemoteServiceID:  sourceService,
			RemoteVersion:    instance.Subject.Properties["sourceVersion"].GetStringValue(),
			Endpoint:         fmt.Sprintf("path:%s", instance.Action.Path),
			Method:           instance.Action.Method,
		}
	}

	code := s.octarine.HandleP2PRequest(true, liboctarine.CheckOnly, isIncoming, request)
	glog.Infof("Result from liboctarine: %d", code)

	statusCode := int32(0)
	statusMsg := ""

	switch code {
	case liboctarine.BLOCK:
		statusCode = 16
		statusMsg = "traffic has been blocked by rule"
	case liboctarine.ALERT:
		statusMsg = "traffic has been alerted by rule"
	}

	status := rpc.Status{
		Code:    statusCode,
		Message: statusMsg,
	}

	result := &v1beta1.CheckResult{
		Status:        status,
		ValidDuration: time.Duration(30 * time.Second),
		ValidUseCount: 1000,
	}

	glog.Infof("Sending result: %+v\n", result)

	return result, nil
}

// Addr returns the listening address of the server
func (s *OctarineAdapter) Addr() string {
	return s.listener.Addr().String()
}

// Run starts the server run
func (s *OctarineAdapter) Run(shutdown chan error) {
	shutdown <- s.server.Serve(s.listener)
}

// Close gracefully shuts down the server; used for testing
func (s *OctarineAdapter) Close() error {
	if s.server != nil {
		s.server.GracefulStop()
	}

	if s.listener != nil {
		_ = s.listener.Close()
	}

	return nil
}

// NewOctarineAdapter creates a new IBP adapter that listens at provided port.
func NewOctarineAdapter(port string, proxyAddress string, proxyCACertFile string,
	backendAddress string, accessTokenFile string, flagsFile string) (Server, error) {
	// l := liboctarine.LibOctarine{
	// 	MessageProxyAddress: proxyAddress,
	// 	MessageProxyCACert:  proxyCACertFile,
	// 	BackendAddress:      backendAddress,
	// 	InitialAccessToken:  accessTokenFile,
	// }

	l := liboctarine.LibOctarine{
		FlagsFileName: flagsFile,
	}

	if err := l.Init(); err != nil {
		return nil, err
	}

	if port == "" {
		port = "0"
	}
	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		return nil, fmt.Errorf("unable to listen on socket: %v", err)
	}

	s := &OctarineAdapter{
		listener: listener,
		octarine: l,
	}

	fmt.Printf("listening on \"%v\"\n", s.Addr())
	s.server = grpc.NewServer()
	authorization.RegisterHandleAuthorizationServiceServer(s.server, s)
	logentry.RegisterHandleLogEntryServiceServer(s.server, s)
	return s, nil
}
