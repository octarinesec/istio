//go:generate $GOPATH/src/istio.io/istio/bin/mixer_codegen.sh -f mixer/adapter/octarine/config/config.proto

package octarine

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gogo/googleapis/google/rpc"
	"golang.octarinesec.com/liboctarine"
	"istio.io/istio/mixer/adapter/octarine/config"
	"istio.io/istio/mixer/pkg/adapter"
	"istio.io/istio/mixer/template/authorization"
	"istio.io/istio/mixer/template/logentry"
)

type (
	builder struct {
		adpCfg             *config.Params
		logentryTypes      map[string]*logentry.Type
		authorizationTypes map[string]*authorization.Type
	}
	handler struct {
		octarine           liboctarine.LibOctarine
		deployment         string
		logentryTypes      map[string]*logentry.Type
		authorizationTypes map[string]*authorization.Type
		env                adapter.Env
	}
)

// ensure types implement the requisite interfaces
var _ logentry.HandlerBuilder = &builder{}
var _ logentry.Handler = &handler{}

var _ authorization.HandlerBuilder = &builder{}
var _ authorization.Handler = &handler{}

///////////////// Configuration-time Methods ///////////////

// adapter.HandlerBuilder#Build
func (b *builder) Build(ctx context.Context, env adapter.Env) (adapter.Handler, error) {
	var l liboctarine.LibOctarine

	if b.adpCfg.FlagsFile != "" {
		if _, err := os.Stat(b.adpCfg.FlagsFile); os.IsNotExist(err) {
			return nil, fmt.Errorf("FlagsFile '%s' does not exist", b.adpCfg.FlagsFile)
		}

		l = liboctarine.LibOctarine{
			FlagsFileName: b.adpCfg.FlagsFile,
		}
	} else {
		l = liboctarine.LibOctarine{
			Namespace:           b.adpCfg.Namespace,
			MessageProxyAddress: b.adpCfg.MessageProxyAddress,
			MessageProxyCACert:  b.adpCfg.MessageProxyCA,
			BackendAddress:      b.adpCfg.BackendAddress,
			InitialAccessToken:  b.adpCfg.InitialAccessToken,
		}
	}

	l.Init()
	return &handler{
		octarine:      l,
		deployment:    b.adpCfg.Deployment,
		logentryTypes: b.logentryTypes,
		env:           env,
	}, nil
}

// adapter.HandlerBuilder#SetAdapterConfig
func (b *builder) SetAdapterConfig(cfg adapter.Config) {
	b.adpCfg = cfg.(*config.Params)
}

// adapter.HandlerBuilder#Validate
func (b *builder) Validate() (ce *adapter.ConfigErrors) {
	if _, err := filepath.Abs(b.adpCfg.MessageProxyCA); err != nil {
		ce = ce.Append("messageProxyCA", err)
	}
	return
}

// logentry.HandlerBuilder#SetLogEntryTypes
func (b *builder) SetLogEntryTypes(types map[string]*logentry.Type) {
	b.logentryTypes = types
}

// authorization.HandlerBuilder#SetAuthorizationTypes
func (b *builder) SetAuthorizationTypes(types map[string]*authorization.Type) {
	b.authorizationTypes = types
}

////////////////// Request-time Methods //////////////////////////

// authorization.Handler#HandleAuthorization
func (h *handler) HandleAuthorization(ctx context.Context, instance *authorization.Instance) (adapter.CheckResult, error) {
	sourceSocket := liboctarine.ExternalSocketInfo{
		Address: instance.Subject.Properties["sourceIp"].(net.IP).String(),
	}

	destinationSocket := liboctarine.ExternalSocketInfo{
		Address: instance.Action.Properties["destinationIp"].(net.IP).String(),
	}

	sourceName := instance.Subject.Properties["sourceName"].(string)
	if sourceName == "" {
		e := strings.Split(instance.Subject.Properties["sourceAddress"].(string), ".")
		if len(e) > 0 {
			sourceName = e[0]
		}
	}

	destinationName := instance.Action.Properties["destinationName"].(string)
	if destinationName == "" {
		e := strings.Split(instance.Action.Service, ".")
		if len(e) > 0 {
			destinationName = e[0]
		}
	}

	sourceService := fmt.Sprintf("%s:%s@%s",
		instance.Subject.Properties["sourceNamespace"].(string),
		sourceName,
		h.deployment,
	)

	destinationService := fmt.Sprintf("%s:%s@%s",
		instance.Action.Namespace,
		destinationName,
		h.deployment,
	)

	var outbound bool
	// If the destination UID is empty, this is egress traffic which means it's outbound.
	if instance.Action.Properties["destinationUid"].(string) == "" {
		outbound = true
	} else {
		outbound = false
	}

	var request liboctarine.ExternalRequest
	var isIncoming int

	if outbound {
		isIncoming = 2
		request = liboctarine.ExternalRequest{
			Protocol:         instance.Action.Properties["protocol"].(string),
			MessageID:        0,
			RemoteMessageID:  0,
			LocalSocketInfo:  sourceSocket,
			LocalInstanceID:  instance.Subject.Properties["sourceUid"].(string),
			LocalServiceID:   sourceService,
			LocalVersion:     instance.Subject.Properties["sourceVersion"].(string),
			RemoteSocketInfo: destinationSocket,
			RemoteInstanceID: instance.Action.Properties["destinationUid"].(string),
			RemoteServiceID:  destinationService,
			RemoteVersion:    instance.Action.Properties["destinationVersion"].(string),
			Endpoint:         fmt.Sprintf("path:%s", instance.Action.Path),
			Method:           instance.Action.Method,
		}
	} else {
		isIncoming = 1
		request = liboctarine.ExternalRequest{
			Protocol:         instance.Action.Properties["protocol"].(string),
			MessageID:        0,
			RemoteMessageID:  0,
			LocalSocketInfo:  destinationSocket,
			LocalInstanceID:  instance.Action.Properties["destinationUid"].(string),
			LocalServiceID:   destinationService,
			LocalVersion:     instance.Action.Properties["destinationVersion"].(string),
			RemoteSocketInfo: sourceSocket,
			RemoteInstanceID: instance.Subject.Properties["sourceUid"].(string),
			RemoteServiceID:  sourceService,
			RemoteVersion:    instance.Subject.Properties["sourceVersion"].(string),
			Endpoint:         fmt.Sprintf("path:%s", instance.Action.Path),
			Method:           instance.Action.Method,
		}
	}

	code := h.octarine.HandleP2PRequest(true, liboctarine.CheckOnly, isIncoming, request)

	statusCode := int32(0)
	statusMsg := ""

	switch code {
	case liboctarine.BLOCK:
		statusCode = 16
		statusMsg = "traffic has been blocked by rule"
	case liboctarine.ALERT:
		statusMsg = "traffic has been alerted by rule"
	}

	s := rpc.Status{
		Code:    statusCode,
		Message: statusMsg,
	}

	result := adapter.CheckResult{
		Status:        s,
		ValidDuration: time.Duration(30 * time.Second),
		ValidUseCount: 1000,
	}

	h.env.Logger().Infof("Sending result: %+v\n", result)

	return result, nil
}

// logentry.Handler#HandleLogEntry
func (h *handler) HandleLogEntry(ctx context.Context, instances []*logentry.Instance) error {
	for _, instance := range instances {
		if _, ok := h.logentryTypes[instance.Name]; !ok {
			h.env.Logger().Errorf("Cannot find Type for instance %s", instance.Name)
			continue
		}

		sourceSocket := liboctarine.ExternalSocketInfo{
			Address: instance.Variables["sourceIp"].(net.IP).String(),
		}

		destinationSocket := liboctarine.ExternalSocketInfo{
			Address: instance.Variables["destinationIp"].(net.IP).String(),
		}

		sourceName := instance.Variables["sourceName"].(string)
		if sourceName == "" {
			e := strings.Split(instance.Variables["sourceAddress"].(string), ".")
			if len(e) > 0 {
				sourceName = e[0]
			}
		}

		destinationName := instance.Variables["destinationName"].(string)
		if destinationName == "" {
			e := strings.Split(instance.Variables["destinationAddress"].(string), ".")
			if len(e) > 0 {
				destinationName = e[0]
			}
		}

		sourceService := fmt.Sprintf("%s:%s@%s",
			instance.Variables["sourceNamespace"].(string),
			sourceName,
			h.deployment,
		)

		destinationService := fmt.Sprintf("%s:%s@%s",
			instance.Variables["destinationNamespace"].(string),
			destinationName,
			h.deployment,
		)

		// If the response duration is 0, we're most likely outbound
		zeroDuration, _ := time.ParseDuration("0ms")
		outbound := instance.Variables["responseDuration"].(time.Duration) == zeroDuration

		var request liboctarine.ExternalRequest
		var isIncoming int

		if outbound {
			isIncoming = 2
			request = liboctarine.ExternalRequest{
				Protocol:         instance.Variables["protocol"].(string),
				MessageID:        0,
				RemoteMessageID:  0,
				LocalSocketInfo:  sourceSocket,
				LocalInstanceID:  instance.Variables["sourceUid"].(string),
				LocalServiceID:   sourceService,
				LocalVersion:     instance.Variables["sourceVersion"].(string),
				RemoteSocketInfo: destinationSocket,
				RemoteInstanceID: instance.Variables["destinationUid"].(string),
				RemoteServiceID:  destinationService,
				RemoteVersion:    instance.Variables["destinationVersion"].(string),
				Endpoint:         fmt.Sprintf("path:%s", instance.Variables["endpoint"].(string)),
				Method:           instance.Variables["method"].(string),
			}
		} else {
			isIncoming = 1
			request = liboctarine.ExternalRequest{
				Protocol:         instance.Variables["protocol"].(string),
				MessageID:        0,
				RemoteMessageID:  0,
				LocalSocketInfo:  destinationSocket,
				LocalInstanceID:  instance.Variables["destinationUid"].(string),
				LocalServiceID:   destinationService,
				LocalVersion:     instance.Variables["destinationVersion"].(string),
				RemoteSocketInfo: sourceSocket,
				RemoteInstanceID: instance.Variables["sourceUid"].(string),
				RemoteServiceID:  sourceService,
				RemoteVersion:    instance.Variables["sourceVersion"].(string),
				Endpoint:         fmt.Sprintf("path:%s", instance.Variables["endpoint"].(string)),
				Method:           instance.Variables["method"].(string),
			}
		}

		h.octarine.HandleP2PRequest(true, liboctarine.CheckAndLog, isIncoming, request)
	}
	return nil
}

// adapter.Handler#Close
func (h *handler) Close() error {
	return nil
}

////////////////// Bootstrap //////////////////////////

// GetInfo returns the adapter.Info specific to this adapter.
func GetInfo() adapter.Info {
	return adapter.Info{
		Name:        "octarine",
		Description: "Logs and authorizes activity in the system.",
		SupportedTemplates: []string{
			logentry.TemplateName,
			authorization.TemplateName,
		},
		NewBuilder:    func() adapter.HandlerBuilder { return &builder{} },
		DefaultConfig: &config.Params{},
	}
}
