// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package runner

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	coreconfigv3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerconfigv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routeconfigv3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
	runtimev3 "github.com/envoyproxy/go-control-plane/envoy/service/runtime/v3"
	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"github.com/telepresenceio/watchable"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	ktypes "k8s.io/apimachinery/pkg/types"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/internal/crypto"
	"github.com/envoyproxy/gateway/internal/envoygateway/config"
	extension "github.com/envoyproxy/gateway/internal/extension/types"
	"github.com/envoyproxy/gateway/internal/infrastructure/host"
	"github.com/envoyproxy/gateway/internal/infrastructure/kubernetes/ratelimit"
	"github.com/envoyproxy/gateway/internal/message"
	"github.com/envoyproxy/gateway/internal/utils"
	"github.com/envoyproxy/gateway/internal/xds/bootstrap"
	"github.com/envoyproxy/gateway/internal/xds/cache"
	"github.com/envoyproxy/gateway/internal/xds/server/kubejwt"
	"github.com/envoyproxy/gateway/internal/xds/translator"
	xdstypes "github.com/envoyproxy/gateway/internal/xds/types"
	xdsutils "github.com/envoyproxy/gateway/internal/xds/utils"
)

const (
	// XdsServerAddress is the listening address of the xds-server.
	XdsServerAddress = "0.0.0.0"

	// Default certificates path for envoy-gateway with Kubernetes provider.
	// xdsTLSCertFilepath is the fully qualified path of the file containing the
	// xDS server TLS certificate.
	xdsTLSCertFilepath = "/certs/tls.crt"
	// xdsTLSKeyFilepath is the fully qualified path of the file containing the
	// xDS server TLS key.
	xdsTLSKeyFilepath = "/certs/tls.key"
	// xdsTLSCaFilepath is the fully qualified path of the file containing the
	// xDS server trusted CA certificate.
	xdsTLSCaFilepath = "/certs/ca.crt"

	// defaultKubernetesIssuer is the default issuer URL for Kubernetes.
	// This is used for validating Service Account JWT tokens.
	defaultKubernetesIssuer = "https://kubernetes.default.svc.cluster.local"

	defaultMaxConnectionAgeGrace = 2 * time.Minute
)

var tracer = otel.Tracer("envoy-gateway/xds")

var maxConnectionAgeValues = []time.Duration{
	10 * time.Hour,
	11 * time.Hour,
	12 * time.Hour,
}

type Config struct {
	config.Server
	grpc              *grpc.Server
	cache             cache.SnapshotCacheWithCallbacks
	XdsIR             *message.XdsIR
	ExtensionManager  extension.Manager
	ProviderResources *message.ProviderResources
	RunnerErrors      *message.RunnerErrors
	// Test-configurable TLS paths
	TLSCertPath string
	TLSKeyPath  string
	TLSCaPath   string
}

type Runner struct {
	Config
	lastSnapshotDigests         map[string]string
	lastSnapshotResourceDigests map[string]map[string]string
	lastSnapshotResourceJSON    map[string]map[string]string
	lastSnapshotResourceDetails map[string]map[string]map[string]xdsResourceDetailDigest
	lastSnapshotOrderDigests    map[string]map[string]xdsResourceOrderDigest
}

func New(cfg *Config) *Runner {
	return &Runner{
		Config:                      *cfg,
		lastSnapshotDigests:         make(map[string]string),
		lastSnapshotResourceDigests: make(map[string]map[string]string),
		lastSnapshotResourceJSON:    make(map[string]map[string]string),
		lastSnapshotResourceDetails: make(map[string]map[string]map[string]xdsResourceDetailDigest),
		lastSnapshotOrderDigests:    make(map[string]map[string]xdsResourceOrderDigest),
	}
}

func (r *Runner) Name() string {
	return string(egv1a1.LogComponentXdsRunner)
}

func (r *Runner) serverKeepaliveParams() (keepalive.ServerParameters, error) {
	params := keepalive.ServerParameters{
		MaxConnectionAge:      getRandomMaxConnectionAge(),
		MaxConnectionAgeGrace: defaultMaxConnectionAgeGrace,
	}

	if r.EnvoyGateway == nil || r.EnvoyGateway.XDSServer == nil {
		return params, nil
	}

	cfg := r.EnvoyGateway.XDSServer

	if cfg.MaxConnectionAge != nil {
		d, err := time.ParseDuration(string(*cfg.MaxConnectionAge))
		if err != nil {
			return keepalive.ServerParameters{}, fmt.Errorf("invalid xdsServer.maxConnectionAge: %w", err)
		}
		if d <= 0 {
			return keepalive.ServerParameters{}, fmt.Errorf("xdsServer.maxConnectionAge must be greater than zero")
		}
		params.MaxConnectionAge = d
	}

	if cfg.MaxConnectionAgeGrace != nil {
		d, err := time.ParseDuration(string(*cfg.MaxConnectionAgeGrace))
		if err != nil {
			return keepalive.ServerParameters{}, fmt.Errorf("invalid xdsServer.maxConnectionAgeGrace: %w", err)
		}
		if d <= 0 {
			return keepalive.ServerParameters{}, fmt.Errorf("xdsServer.maxConnectionAgeGrace must be greater than zero")
		}
		params.MaxConnectionAgeGrace = d
	}

	return params, nil
}

// getRandomMaxConnectionAge picks a random maxConnectionAge value
// to spread out envoy proxy connections over multiple envoy gateway replicas
func getRandomMaxConnectionAge() time.Duration {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec
	return maxConnectionAgeValues[rnd.Intn(len(maxConnectionAgeValues))]
}

// Close implements Runner interface.
func (r *Runner) Close() error { return nil }

// Start starts the xds-server runner
func (r *Runner) Start(ctx context.Context) error {
	r.Logger = r.Logger.WithName(r.Name()).WithValues("runner", r.Name())
	r.cache = cache.NewSnapshotCache(true, r.Logger)

	// Set up the gRPC server and register the xDS handler.
	// Create SnapshotCache before start subscribeAndTranslate,
	// prevent panics in case cache is nil.
	tlsConfig, err := r.loadTLSConfig()
	if err != nil {
		return fmt.Errorf("failed to load TLS config: %w", err)
	}
	r.Logger.Info("loaded TLS certificate and key")

	keepaliveParams, err := r.serverKeepaliveParams()
	if err != nil {
		return err
	}
	r.Logger.Info("configured gRPC keepalive", "maxConnectionAge", keepaliveParams.MaxConnectionAge, "maxConnectionAgeGrace", keepaliveParams.MaxConnectionAgeGrace)

	enforcementPolicy := keepalive.EnforcementPolicy{
		MinTime:             15 * time.Second,
		PermitWithoutStream: true,
	}

	baseKeepaliveOptions := []grpc.ServerOption{
		grpc.KeepaliveEnforcementPolicy(enforcementPolicy),
		grpc.KeepaliveParams(keepaliveParams),
	}

	grpcOpts := append([]grpc.ServerOption{}, baseKeepaliveOptions...)
	grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))

	// When GatewayNamespaceMode is enabled, we will use sTLS and Service Account JWT tokens to authenticate envoy proxy infra and xds server.
	if r.EnvoyGateway.GatewayNamespaceMode() {
		r.Logger.Info("gatewayNamespaceMode is enabled, setting up JWTAuthInterceptor and sTLS server")
		clientset, err := kubejwt.GetKubernetesClient()
		if err != nil {
			return fmt.Errorf("failed to create Kubernetes client: %w", err)
		}
		saAudience := fmt.Sprintf("%s.%s.svc.%s", config.EnvoyGatewayServiceName, r.ControllerNamespace, r.DNSDomain)
		jwtInterceptor := kubejwt.NewJWTAuthInterceptor(
			r.Logger,
			clientset,
			defaultKubernetesIssuer,
			saAudience,
		)

		creds, err := credentials.NewServerTLSFromFile(xdsTLSCertFilepath, xdsTLSKeyFilepath)
		if err != nil {
			return fmt.Errorf("failed to create TLS credentials: %w", err)
		}

		grpcOpts = append([]grpc.ServerOption{}, baseKeepaliveOptions...)
		grpcOpts = append(grpcOpts,
			grpc.Creds(creds),
			grpc.StreamInterceptor(jwtInterceptor.Stream()),
		)
	}

	r.grpc = grpc.NewServer(grpcOpts...)
	registerServer(serverv3.NewServer(ctx, r.cache, r.cache), r.grpc)

	// Start and listen xDS gRPC Server.
	go r.serveXdsServer(ctx)

	// Do not call .Subscribe() inside Goroutine since it is supposed to be called from the same
	// Goroutine where Close() is called.
	sub := r.XdsIR.Subscribe(ctx)
	go r.translateFromSubscription(sub)
	r.Logger.Info("started")
	return err
}

func (r *Runner) serveXdsServer(ctx context.Context) {
	addr := net.JoinHostPort(XdsServerAddress, strconv.Itoa(bootstrap.DefaultXdsServerPort))
	l, err := net.Listen("tcp", addr)
	if err != nil {
		r.Logger.Error(err, "failed to listen on address", "address", addr)
		return
	}

	go func() {
		<-ctx.Done()
		r.Logger.Info("grpc server shutting down")
		// We don't use GracefulStop here because envoy
		// has long-lived hanging xDS requests. There's no
		// mechanism to make those pending requests fail,
		// so we forcibly terminate the TCP sessions.
		r.grpc.Stop()
	}()

	if err = r.grpc.Serve(l); err != nil {
		r.Logger.Error(err, "failed to start grpc based xds server")
	}
}

// registerServer registers the given xDS protocol Server with the gRPC
// runtime.
func registerServer(srv serverv3.Server, g *grpc.Server) {
	// register services
	discoveryv3.RegisterAggregatedDiscoveryServiceServer(g, srv)
	secretv3.RegisterSecretDiscoveryServiceServer(g, srv)
	clusterv3.RegisterClusterDiscoveryServiceServer(g, srv)
	endpointv3.RegisterEndpointDiscoveryServiceServer(g, srv)
	listenerv3.RegisterListenerDiscoveryServiceServer(g, srv)
	routev3.RegisterRouteDiscoveryServiceServer(g, srv)
	runtimev3.RegisterRuntimeDiscoveryServiceServer(g, srv)
}

func (r *Runner) translateFromSubscription(sub <-chan watchable.Snapshot[string, *message.XdsIRWithContext]) {
	// Subscribe to resources
	message.HandleSubscription(
		r.Logger,
		message.Metadata{Runner: r.Name(), Message: message.XDSIRMessageName}, sub,
		func(update message.Update[string, *message.XdsIRWithContext], errChan chan error) {
			parentCtx := context.Background()
			if update.Value != nil && update.Value.Context != nil {
				parentCtx = update.Value.Context
			}

			traceCtx, span := tracer.Start(parentCtx, "XdsRunner.subscribeAndTranslate")
			defer span.End()
			traceLogger := r.Logger.WithTrace(traceCtx)
			traceLogger.Info("received an update")

			key := update.Key
			val := update.Value

			// Add span attributes for observability
			span.SetAttributes(
				attribute.String("xds-ir.key", update.Key),
				attribute.Bool("update.delete", update.Delete),
			)

			if update.Delete {
				if err := r.cache.GenerateNewSnapshot(key, nil, traceCtx); err != nil {
					traceLogger.Error(err, "failed to delete the snapshot")
					errChan <- err
				}
			} else {
				// Translate to xds resources
				t := &translator.Translator{
					ControllerNamespace: r.ControllerNamespace,
					FilterOrder:         val.XdsIR.FilterOrder,
					RuntimeFlags:        r.EnvoyGateway.RuntimeFlags,
					Logger:              traceLogger,
				}

				// Set the extension manager if an extension is loaded
				if r.ExtensionManager != nil {
					t.ExtensionManager = &r.ExtensionManager
				}

				// Set the rate limit service URL if global rate limiting is enabled.
				if r.EnvoyGateway.RateLimit != nil {
					t.GlobalRateLimit = &translator.GlobalRateLimitSettings{
						ServiceURL: ratelimit.GetServiceURL(r.ControllerNamespace, r.DNSDomain),
						FailClosed: r.EnvoyGateway.RateLimit.FailClosed,
					}
					if r.EnvoyGateway.RateLimit.Timeout != nil {
						d, err := time.ParseDuration(string(*r.EnvoyGateway.RateLimit.Timeout))
						if err != nil {
							traceLogger.Error(err, "invalid rateLimit timeout")
							errChan <- err
						} else {
							t.GlobalRateLimit.Timeout = d
						}
					}
				}

				_, translateSpan := tracer.Start(traceCtx, "Translator.Translate")
				result, err := t.Translate(val.XdsIR)
				translateSpan.End()
				if err != nil {
					traceLogger.Error(err, "skipped publishing xds resources: failed to translate xds ir")
					errChan <- err
				}

				// xDS translation is done in a best-effort manner, so the result
				// may contain partial resources even if there are errors.
				if result == nil {
					traceLogger.Info("no xds resources to publish")
					return
				}

				// Only update the snapshot cache when there are no system-level errors, to avoid publishing partial resources.
				// This allows Envoy to continue using the previous known-good snapshot until the next successful translation.
				// Note: invalid EnvoyPatchPolicies are considered user-level errors and will not prevent the snapshot from being updated.
				if err == nil {
					if result.XdsResources != nil {
						if r.cache == nil {
							r.Logger.Error(err, "failed to init snapshot cache")
							errChan <- err
						} else {
							digest, count, digestErr := xdsResourcesDigest(result.XdsResources)
							if r.lastSnapshotDigests == nil {
								r.lastSnapshotDigests = make(map[string]string)
							}
							if r.lastSnapshotResourceDigests == nil {
								r.lastSnapshotResourceDigests = make(map[string]map[string]string)
							}
							if r.lastSnapshotResourceJSON == nil {
								r.lastSnapshotResourceJSON = make(map[string]map[string]string)
							}
							if r.lastSnapshotResourceDetails == nil {
								r.lastSnapshotResourceDetails = make(map[string]map[string]map[string]xdsResourceDetailDigest)
							}
							if r.lastSnapshotOrderDigests == nil {
								r.lastSnapshotOrderDigests = make(map[string]map[string]xdsResourceOrderDigest)
							}
							previousDigest := r.lastSnapshotDigests[key]
							equalToPrevious := previousDigest != "" && previousDigest == digest
							if digestErr != nil {
								traceLogger.Error(digestErr, "failed to digest xds resources")
							}
							currentResourceDigests, currentResourceJSON, currentResourceDetails, currentOrderDigests, diffErr := xdsResourceDigests(result.XdsResources)
							if diffErr != nil {
								traceLogger.Error(diffErr, "failed to digest individual xds resources")
							}
							if previousResourceDigests, ok := r.lastSnapshotResourceDigests[key]; ok && !equalToPrevious && diffErr == nil {
								changes := xdsResourceDigestChanges(previousResourceDigests, currentResourceDigests)
								orderChanges := xdsResourceOrderDigestChanges(r.lastSnapshotOrderDigests[key], currentOrderDigests)
								changeLimit := 50
								truncatedChanges := changes
								truncatedOrderChanges := orderChanges
								truncated := false
								if len(truncatedChanges) > changeLimit {
									truncatedChanges = truncatedChanges[:changeLimit]
									truncated = true
								}
								if len(truncatedOrderChanges) > changeLimit {
									truncatedOrderChanges = truncatedOrderChanges[:changeLimit]
									truncated = true
								}
								traceLogger.Info("xds resource digest diff",
									"key", key,
									"resourceChangeCount", len(changes),
									"orderChangeCount", len(orderChanges),
									"truncated", truncated,
									"resourceChanges", truncatedChanges,
									"orderChanges", truncatedOrderChanges,
								)
								previousResourceJSON := r.lastSnapshotResourceJSON[key]
								previousResourceDetails := r.lastSnapshotResourceDetails[key]
								for _, change := range changes {
									resourceKey := change["resource"]
									if resourceKey == "" || change["changeType"] != "changed" {
										continue
									}
									if previousJSON, ok := previousResourceJSON[resourceKey]; ok {
										if currentJSON, ok := currentResourceJSON[resourceKey]; ok {
											structuralDiffs, structuralTruncated, err := xdsResourceStructuralDiffs(previousJSON, currentJSON, 80)
											if err != nil {
												traceLogger.Error(err, "failed to diff changed xds resource json", "key", key, "resource", resourceKey)
											} else if len(structuralDiffs) > 0 {
												traceLogger.Info("xds changed resource structural diff",
													"key", key,
													"resource", resourceKey,
													"previousHash", change["previousHash"],
													"newHash", change["newHash"],
													"diffCount", len(structuralDiffs),
													"truncated", structuralTruncated,
													"diffs", structuralDiffs,
												)
											}
										}
									}
									detailChanges := xdsResourceDetailDigestChanges(previousResourceDetails[resourceKey], currentResourceDetails[resourceKey])
									if len(detailChanges) > 0 {
										detailLimit := 80
										detailChangeCount := len(detailChanges)
										detailTruncated := false
										if len(detailChanges) > detailLimit {
											detailChanges = detailChanges[:detailLimit]
											detailTruncated = true
										}
										traceLogger.Info("xds changed resource component diff",
											"key", key,
											"resource", resourceKey,
											"previousHash", change["previousHash"],
											"newHash", change["newHash"],
											"componentChangeCount", detailChangeCount,
											"truncated", detailTruncated,
											"componentChanges", detailChanges,
										)
									}
								}
							}
							traceLogger.Info("publishing xds snapshot",
								"key", key,
								"equalToPrevious", equalToPrevious,
								"previousHash", previousDigest,
								"newHash", digest,
								"resourceCount", count,
								"resourceTypes", xdsResourceTypeCounts(result.XdsResources),
							)
							r.lastSnapshotDigests[key] = digest
							if diffErr == nil {
								r.lastSnapshotResourceDigests[key] = currentResourceDigests
								r.lastSnapshotResourceJSON[key] = currentResourceJSON
								r.lastSnapshotResourceDetails[key] = currentResourceDetails
								r.lastSnapshotOrderDigests[key] = currentOrderDigests
							}
							// Update snapshot cache
							if err := r.cache.GenerateNewSnapshot(key, result.XdsResources, traceCtx); err != nil {
								r.Logger.Error(err, "failed to generate a snapshot")
								errChan <- err
							}
						}
					} else {
						r.Logger.Error(err, "skipped publishing xds resources")
					}
				}

				// Get all status keys from watchable and save them in the map statusesToDelete.
				// Iterating through result.EnvoyPatchPolicyStatuses, any valid keys will be removed from statusesToDelete.
				// Remaining keys will be deleted from watchable before we exit this function.
				statusesToDelete := make(map[ktypes.NamespacedName]bool)
				for key := range r.ProviderResources.EnvoyPatchPolicyStatuses.LoadAll() {
					statusesToDelete[key] = true
				}

				// Publish EnvoyPatchPolicyStatus
				for _, e := range result.EnvoyPatchPolicyStatuses {
					key := ktypes.NamespacedName{
						Name:      e.Name,
						Namespace: e.Namespace,
					}
					// Skip updating status for policies with empty status
					// They may have been skipped in this translation because
					// their target is not found (not relevant)
					if len(e.Status.Ancestors) > 0 {
						r.ProviderResources.EnvoyPatchPolicyStatuses.Store(key, e.Status)
					}
					delete(statusesToDelete, key)
				}
				// Discard the EnvoyPatchPolicyStatuses to reduce memory footprint
				result.EnvoyPatchPolicyStatuses = nil

				// Delete all the deletable status keys
				for key := range statusesToDelete {
					r.ProviderResources.EnvoyPatchPolicyStatuses.Delete(key)
				}
			}
		},
	)
	r.Logger.Info("subscriber shutting down")
}

func xdsResourcesDigest(resources xdstypes.XdsResources) (string, int, error) {
	if resources == nil {
		return "", 0, nil
	}
	resourceTypes := make([]resourcev3.Type, 0, len(resources))
	count := 0
	for typ, typedResources := range resources {
		resourceTypes = append(resourceTypes, typ)
		count += len(typedResources)
	}
	sort.Slice(resourceTypes, func(i, j int) bool {
		return string(resourceTypes[i]) < string(resourceTypes[j])
	})

	var buf bytes.Buffer
	for _, typ := range resourceTypes {
		typeURL := string(typ)
		typedResources := resources[typ]
		jsonBytes, err := xdsutils.MarshalResourcesToJSON(typedResources)
		if err != nil {
			return "", count, err
		}
		buf.WriteString(typeURL)
		buf.WriteByte('=')
		buf.Write(jsonBytes)
		buf.WriteByte('\n')
	}
	return utils.Digest256(buf.String())[:12], count, nil
}

type xdsResourceOrderDigest struct {
	Hash  string
	Names []string
}

type xdsResourceDetailDigest struct {
	Hash    string
	Summary string
}

func xdsResourceDigests(resources xdstypes.XdsResources) (map[string]string, map[string]string, map[string]map[string]xdsResourceDetailDigest, map[string]xdsResourceOrderDigest, error) {
	resourceDigests := make(map[string]string)
	resourceJSON := make(map[string]string)
	resourceDetails := make(map[string]map[string]xdsResourceDetailDigest)
	orderDigests := make(map[string]xdsResourceOrderDigest)
	if resources == nil {
		return resourceDigests, resourceJSON, resourceDetails, orderDigests, nil
	}

	resourceTypes := make([]resourcev3.Type, 0, len(resources))
	for typ := range resources {
		resourceTypes = append(resourceTypes, typ)
	}
	sort.Slice(resourceTypes, func(i, j int) bool {
		return string(resourceTypes[i]) < string(resourceTypes[j])
	})

	for _, typ := range resourceTypes {
		typeURL := string(typ)
		typedResources := resources[typ]
		names := make([]string, 0, len(typedResources))
		for idx := range typedResources {
			name := xdsResourceName(typedResources[idx], idx)
			names = append(names, name)
			jsonBytes, err := xdsutils.MarshalResourcesToJSON(typedResources[idx : idx+1])
			if err != nil {
				return nil, nil, nil, nil, err
			}
			resourceKey := typeURL + "/" + name
			rawJSON := strings.TrimPrefix(strings.TrimSuffix(string(jsonBytes), "]"), "[")
			resourceDigests[resourceKey] = utils.Digest256(string(jsonBytes))[:12]
			resourceJSON[resourceKey] = rawJSON
			resourceDetails[resourceKey] = xdsResourceDetailDigests(typedResources[idx])
		}
		orderDigests[typeURL] = xdsResourceOrderDigest{
			Hash:  utils.Digest256(fmt.Sprintf("%q", names))[:12],
			Names: names,
		}
	}

	return resourceDigests, resourceJSON, resourceDetails, orderDigests, nil
}

func xdsResourceName(resource any, idx int) string {
	if named, ok := resource.(interface{ GetName() string }); ok {
		if name := named.GetName(); name != "" {
			return name
		}
	}
	return fmt.Sprintf("%T[%d]", resource, idx)
}

func xdsResourceDigestChanges(previous, current map[string]string) []map[string]string {
	keys := make(map[string]struct{}, len(previous)+len(current))
	for key := range previous {
		keys[key] = struct{}{}
	}
	for key := range current {
		keys[key] = struct{}{}
	}

	sortedKeys := make([]string, 0, len(keys))
	for key := range keys {
		sortedKeys = append(sortedKeys, key)
	}
	sort.Strings(sortedKeys)

	changes := make([]map[string]string, 0)
	for _, key := range sortedKeys {
		previousHash, previousFound := previous[key]
		currentHash, currentFound := current[key]
		switch {
		case !previousFound:
			changes = append(changes, map[string]string{
				"changeType": "added",
				"resource":   key,
				"newHash":    currentHash,
			})
		case !currentFound:
			changes = append(changes, map[string]string{
				"changeType":   "removed",
				"resource":     key,
				"previousHash": previousHash,
			})
		case previousHash != currentHash:
			changes = append(changes, map[string]string{
				"changeType":   "changed",
				"resource":     key,
				"previousHash": previousHash,
				"newHash":      currentHash,
			})
		}
	}

	return changes
}

func xdsResourceOrderDigestChanges(previous, current map[string]xdsResourceOrderDigest) []map[string]any {
	keys := make(map[string]struct{}, len(previous)+len(current))
	for key := range previous {
		keys[key] = struct{}{}
	}
	for key := range current {
		keys[key] = struct{}{}
	}

	sortedKeys := make([]string, 0, len(keys))
	for key := range keys {
		sortedKeys = append(sortedKeys, key)
	}
	sort.Strings(sortedKeys)

	changes := make([]map[string]any, 0)
	for _, key := range sortedKeys {
		previousDigest, previousFound := previous[key]
		currentDigest, currentFound := current[key]
		switch {
		case !previousFound:
			changes = append(changes, map[string]any{
				"changeType": "added",
				"type":       key,
				"newHash":    currentDigest.Hash,
				"newOrder":   xdsResourceOrderPreview(currentDigest.Names),
			})
		case !currentFound:
			changes = append(changes, map[string]any{
				"changeType":    "removed",
				"type":          key,
				"previousHash":  previousDigest.Hash,
				"previousOrder": xdsResourceOrderPreview(previousDigest.Names),
			})
		case previousDigest.Hash != currentDigest.Hash:
			changes = append(changes, map[string]any{
				"changeType":    "changed",
				"type":          key,
				"previousHash":  previousDigest.Hash,
				"newHash":       currentDigest.Hash,
				"previousOrder": xdsResourceOrderPreview(previousDigest.Names),
				"newOrder":      xdsResourceOrderPreview(currentDigest.Names),
			})
		}
	}

	return changes
}

func xdsResourceOrderPreview(names []string) []string {
	const limit = 20
	if len(names) <= limit {
		return names
	}
	preview := make([]string, 0, limit+1)
	preview = append(preview, names[:limit]...)
	preview = append(preview, fmt.Sprintf("... %d more", len(names)-limit))
	return preview
}

func xdsResourceStructuralDiffs(previousJSON, currentJSON string, limit int) ([]map[string]any, bool, error) {
	var previous any
	if err := decodeJSONValue(previousJSON, &previous); err != nil {
		return nil, false, err
	}
	var current any
	if err := decodeJSONValue(currentJSON, &current); err != nil {
		return nil, false, err
	}

	diffs := make([]map[string]any, 0)
	truncated := false
	appendJSONDiff("$", previous, current, limit, &diffs, &truncated)
	return diffs, truncated, nil
}

func decodeJSONValue(raw string, out *any) error {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	return decoder.Decode(out)
}

func appendJSONDiff(path string, previous, current any, limit int, diffs *[]map[string]any, truncated *bool) {
	if *truncated {
		return
	}
	if len(*diffs) >= limit {
		*truncated = true
		return
	}

	switch previousValue := previous.(type) {
	case map[string]any:
		currentValue, ok := current.(map[string]any)
		if !ok {
			appendJSONValueDiff(path, previous, current, diffs)
			return
		}
		keys := make(map[string]struct{}, len(previousValue)+len(currentValue))
		for key := range previousValue {
			keys[key] = struct{}{}
		}
		for key := range currentValue {
			keys[key] = struct{}{}
		}
		sortedKeys := make([]string, 0, len(keys))
		for key := range keys {
			sortedKeys = append(sortedKeys, key)
		}
		sort.Strings(sortedKeys)
		for _, key := range sortedKeys {
			nextPath := path + "." + key
			previousChild, previousFound := previousValue[key]
			currentChild, currentFound := currentValue[key]
			switch {
			case !previousFound:
				appendJSONAddedRemovedDiff(nextPath, "added", nil, currentChild, diffs)
			case !currentFound:
				appendJSONAddedRemovedDiff(nextPath, "removed", previousChild, nil, diffs)
			default:
				appendJSONDiff(nextPath, previousChild, currentChild, limit, diffs, truncated)
			}
			if *truncated {
				return
			}
		}
	case []any:
		currentValue, ok := current.([]any)
		if !ok {
			appendJSONValueDiff(path, previous, current, diffs)
			return
		}
		if len(previousValue) != len(currentValue) {
			appendJSONAddedRemovedDiff(path+".length", "changed", len(previousValue), len(currentValue), diffs)
		}
		for idx := 0; idx < min(len(previousValue), len(currentValue)); idx++ {
			appendJSONDiff(fmt.Sprintf("%s[%d]", path, idx), previousValue[idx], currentValue[idx], limit, diffs, truncated)
			if *truncated {
				return
			}
		}
	default:
		if !reflect.DeepEqual(previous, current) {
			appendJSONValueDiff(path, previous, current, diffs)
		}
	}
}

func appendJSONValueDiff(path string, previous, current any, diffs *[]map[string]any) {
	*diffs = append(*diffs, map[string]any{
		"path":         path,
		"changeType":   "changed",
		"previous":     xdsJSONValuePreview(previous),
		"new":          xdsJSONValuePreview(current),
		"previousHash": xdsJSONValueHash(previous),
		"newHash":      xdsJSONValueHash(current),
	})
}

func appendJSONAddedRemovedDiff(path, changeType string, previous, current any, diffs *[]map[string]any) {
	diff := map[string]any{
		"path":       path,
		"changeType": changeType,
	}
	if previous != nil {
		diff["previous"] = xdsJSONValuePreview(previous)
		diff["previousHash"] = xdsJSONValueHash(previous)
	}
	if current != nil {
		diff["new"] = xdsJSONValuePreview(current)
		diff["newHash"] = xdsJSONValueHash(current)
	}
	*diffs = append(*diffs, diff)
}

func xdsJSONValueHash(value any) string {
	if value == nil {
		return ""
	}
	jsonBytes, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("marshal-error:%T", value)
	}
	return utils.Digest256(string(jsonBytes))[:12]
}

func xdsJSONValuePreview(value any) any {
	switch typed := value.(type) {
	case nil:
		return nil
	case string:
		if len(typed) <= 180 {
			return typed
		}
		return typed[:180] + fmt.Sprintf("... %d more bytes", len(typed)-180)
	case json.Number, bool, float64:
		return typed
	case []any:
		return fmt.Sprintf("array len=%d hash=%s", len(typed), xdsJSONValueHash(typed))
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		if len(keys) > 12 {
			keys = append(keys[:12], fmt.Sprintf("... %d more", len(keys)-12))
		}
		return fmt.Sprintf("object keys=%v hash=%s", keys, xdsJSONValueHash(typed))
	default:
		return fmt.Sprintf("%v", typed)
	}
}

func xdsResourceDetailDigestChanges(previous, current map[string]xdsResourceDetailDigest) []map[string]string {
	keys := make(map[string]struct{}, len(previous)+len(current))
	for key := range previous {
		keys[key] = struct{}{}
	}
	for key := range current {
		keys[key] = struct{}{}
	}

	sortedKeys := make([]string, 0, len(keys))
	for key := range keys {
		sortedKeys = append(sortedKeys, key)
	}
	sort.Strings(sortedKeys)

	changes := make([]map[string]string, 0)
	for _, key := range sortedKeys {
		previousDigest, previousFound := previous[key]
		currentDigest, currentFound := current[key]
		switch {
		case !previousFound:
			changes = append(changes, map[string]string{
				"changeType": "added",
				"component":  key,
				"newHash":    currentDigest.Hash,
				"newSummary": currentDigest.Summary,
			})
		case !currentFound:
			changes = append(changes, map[string]string{
				"changeType":      "removed",
				"component":       key,
				"previousHash":    previousDigest.Hash,
				"previousSummary": previousDigest.Summary,
			})
		case previousDigest.Hash != currentDigest.Hash:
			changes = append(changes, map[string]string{
				"changeType":      "changed",
				"component":       key,
				"previousHash":    previousDigest.Hash,
				"newHash":         currentDigest.Hash,
				"previousSummary": previousDigest.Summary,
				"newSummary":      currentDigest.Summary,
			})
		}
	}

	return changes
}

func xdsResourceDetailDigests(resource any) map[string]xdsResourceDetailDigest {
	switch typed := resource.(type) {
	case *listenerconfigv3.Listener:
		return xdsListenerDetailDigests(typed)
	case *routeconfigv3.RouteConfiguration:
		return xdsRouteConfigurationDetailDigests(typed)
	default:
		return nil
	}
}

func xdsListenerDetailDigests(listener *listenerconfigv3.Listener) map[string]xdsResourceDetailDigest {
	details := make(map[string]xdsResourceDetailDigest)
	addProtoDetail(details, "listener.address", listener.GetAddress(), "")
	details["listener.listener_filters.order"] = xdsStringListDetail(xdsListenerFilterNames(listener.GetListenerFilters()))
	details["listener.filter_chains.order"] = xdsStringListDetail(xdsFilterChainSummaries(listener.GetFilterChains()))
	for idx, filterChain := range listener.GetFilterChains() {
		prefix := fmt.Sprintf("listener.filter_chains[%03d]", idx)
		addProtoDetail(details, prefix, filterChain, xdsFilterChainSummary(filterChain))
		addProtoDetail(details, prefix+".match", filterChain.GetFilterChainMatch(), "")
		details[prefix+".filters.order"] = xdsStringListDetail(xdsNetworkFilterNames(filterChain.GetFilters()))
		for filterIdx, filter := range filterChain.GetFilters() {
			filterPrefix := fmt.Sprintf("%s.filters[%03d]", prefix, filterIdx)
			addProtoDetail(details, filterPrefix, filter, xdsNetworkFilterSummary(filter))
		}
		addProtoDetail(details, prefix+".transport_socket", filterChain.GetTransportSocket(), xdsTransportSocketSummary(filterChain.GetTransportSocket()))
	}
	return details
}

func xdsRouteConfigurationDetailDigests(routeConfig *routeconfigv3.RouteConfiguration) map[string]xdsResourceDetailDigest {
	details := make(map[string]xdsResourceDetailDigest)
	details["route_config.virtual_hosts.order"] = xdsStringListDetail(xdsVirtualHostSummaries(routeConfig.GetVirtualHosts()))
	for vhostIdx, vhost := range routeConfig.GetVirtualHosts() {
		vhostPrefix := fmt.Sprintf("route_config.virtual_hosts[%03d]", vhostIdx)
		addProtoDetail(details, vhostPrefix, vhost, xdsVirtualHostSummary(vhost))
		details[vhostPrefix+".domains"] = xdsStringListDetail(vhost.GetDomains())
		details[vhostPrefix+".routes.order"] = xdsStringListDetail(xdsRouteSummaries(vhost.GetRoutes()))
		for routeIdx, route := range vhost.GetRoutes() {
			routePrefix := fmt.Sprintf("%s.routes[%03d]", vhostPrefix, routeIdx)
			addProtoDetail(details, routePrefix, route, xdsRouteSummary(route))
			addProtoDetail(details, routePrefix+".match", route.GetMatch(), "")
			addProtoDetail(details, routePrefix+".action", route.GetRoute(), xdsRouteActionSummary(route.GetRoute()))
			details[routePrefix+".typed_per_filter_config.keys"] = xdsStringListDetail(xdsSortedMapKeys(route.GetTypedPerFilterConfig()))
		}
	}
	return details
}

func addProtoDetail(details map[string]xdsResourceDetailDigest, path string, msg proto.Message, summary string) {
	if msg == nil {
		details[path] = xdsResourceDetailDigest{Hash: "", Summary: summary}
		return
	}
	details[path] = xdsResourceDetailDigest{
		Hash:    xdsProtoMessageDigest(msg),
		Summary: summary,
	}
}

func xdsProtoMessageDigest(msg proto.Message) string {
	jsonBytes, err := protojson.Marshal(msg)
	if err != nil {
		return fmt.Sprintf("marshal-error:%T", msg)
	}
	return utils.Digest256(string(jsonBytes))[:12]
}

func xdsStringListDetail(values []string) xdsResourceDetailDigest {
	return xdsResourceDetailDigest{
		Hash:    utils.Digest256(fmt.Sprintf("%q", values))[:12],
		Summary: strings.Join(xdsStringListPreview(values, 12), ","),
	}
}

func xdsStringListPreview(values []string, limit int) []string {
	if len(values) <= limit {
		return values
	}
	preview := make([]string, 0, limit+1)
	preview = append(preview, values[:limit]...)
	preview = append(preview, fmt.Sprintf("... %d more", len(values)-limit))
	return preview
}

func xdsListenerFilterNames(filters []*listenerconfigv3.ListenerFilter) []string {
	names := make([]string, 0, len(filters))
	for _, filter := range filters {
		names = append(names, filter.GetName())
	}
	return names
}

func xdsNetworkFilterNames(filters []*listenerconfigv3.Filter) []string {
	names := make([]string, 0, len(filters))
	for _, filter := range filters {
		typeURL := ""
		if typedConfig := filter.GetTypedConfig(); typedConfig != nil {
			typeURL = typedConfig.GetTypeUrl()
		}
		names = append(names, filter.GetName()+"|"+typeURL)
	}
	return names
}

func xdsFilterChainSummaries(filterChains []*listenerconfigv3.FilterChain) []string {
	summaries := make([]string, 0, len(filterChains))
	for _, filterChain := range filterChains {
		summaries = append(summaries, xdsFilterChainSummary(filterChain))
	}
	return summaries
}

func xdsFilterChainSummary(filterChain *listenerconfigv3.FilterChain) string {
	if filterChain == nil {
		return ""
	}
	match := filterChain.GetFilterChainMatch()
	if match == nil {
		return filterChain.GetName()
	}
	parts := []string{
		"name=" + filterChain.GetName(),
		"sni=" + strings.Join(match.GetServerNames(), "|"),
		"transport=" + match.GetTransportProtocol(),
		"app=" + strings.Join(match.GetApplicationProtocols(), "|"),
	}
	return strings.Join(parts, " ")
}

func xdsNetworkFilterSummary(filter *listenerconfigv3.Filter) string {
	if filter == nil {
		return ""
	}
	typeURL := ""
	if typedConfig := filter.GetTypedConfig(); typedConfig != nil {
		typeURL = typedConfig.GetTypeUrl()
	}
	return filter.GetName() + "|" + typeURL
}

func xdsTransportSocketSummary(socket *coreconfigv3.TransportSocket) string {
	if socket == nil {
		return ""
	}
	typeURL := ""
	if typedConfig := socket.GetTypedConfig(); typedConfig != nil {
		typeURL = typedConfig.GetTypeUrl()
	}
	return socket.GetName() + "|" + typeURL
}

func xdsVirtualHostSummaries(vhosts []*routeconfigv3.VirtualHost) []string {
	summaries := make([]string, 0, len(vhosts))
	for _, vhost := range vhosts {
		summaries = append(summaries, xdsVirtualHostSummary(vhost))
	}
	return summaries
}

func xdsVirtualHostSummary(vhost *routeconfigv3.VirtualHost) string {
	if vhost == nil {
		return ""
	}
	return vhost.GetName() + " domains=" + strings.Join(vhost.GetDomains(), "|")
}

func xdsRouteSummaries(routes []*routeconfigv3.Route) []string {
	summaries := make([]string, 0, len(routes))
	for _, route := range routes {
		summaries = append(summaries, xdsRouteSummary(route))
	}
	return summaries
}

func xdsRouteSummary(route *routeconfigv3.Route) string {
	if route == nil {
		return ""
	}
	return route.GetName() + " match=" + xdsProtoMessageDigest(route.GetMatch()) + " action=" + xdsRouteActionSummary(route.GetRoute())
}

func xdsRouteActionSummary(action *routeconfigv3.RouteAction) string {
	if action == nil {
		return ""
	}
	switch cluster := action.GetClusterSpecifier().(type) {
	case *routeconfigv3.RouteAction_Cluster:
		return "cluster=" + cluster.Cluster
	case *routeconfigv3.RouteAction_WeightedClusters:
		names := make([]string, 0, len(cluster.WeightedClusters.GetClusters()))
		for _, weightedCluster := range cluster.WeightedClusters.GetClusters() {
			names = append(names, weightedCluster.GetName()+":"+fmt.Sprint(weightedCluster.GetWeight().GetValue()))
		}
		return "weighted=" + strings.Join(names, "|")
	case *routeconfigv3.RouteAction_ClusterHeader:
		return "clusterHeader=" + cluster.ClusterHeader
	default:
		return fmt.Sprintf("%T", cluster)
	}
}

func xdsSortedMapKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func xdsResourceTypeCounts(resources xdstypes.XdsResources) []any {
	if resources == nil {
		return nil
	}
	resourceTypes := make([]resourcev3.Type, 0, len(resources))
	for typ := range resources {
		resourceTypes = append(resourceTypes, typ)
	}
	sort.Slice(resourceTypes, func(i, j int) bool {
		return string(resourceTypes[i]) < string(resourceTypes[j])
	})

	counts := make([]any, 0, len(resourceTypes)*2)
	for _, typ := range resourceTypes {
		counts = append(counts, string(typ), len(resources[typ]))
	}
	return counts
}

func (r *Runner) loadTLSConfig() (*tls.Config, error) {
	var certPath, keyPath, caPath string

	// Use test-configurable paths if provided
	if r.TLSCertPath != "" && r.TLSKeyPath != "" && r.TLSCaPath != "" {
		certPath = r.TLSCertPath
		keyPath = r.TLSKeyPath
		caPath = r.TLSCaPath
	} else {
		// Use default paths based on provider type
		switch {
		case r.EnvoyGateway.Provider.IsRunningOnKubernetes():
			certPath = xdsTLSCertFilepath
			keyPath = xdsTLSKeyFilepath
			caPath = xdsTLSCaFilepath
		case r.EnvoyGateway.Provider.IsRunningOnHost():
			// Get config
			var hostCfg *egv1a1.EnvoyGatewayHostInfrastructureProvider
			if p := r.EnvoyGateway.Provider; p != nil && p.Custom != nil &&
				p.Custom.Infrastructure != nil && p.Custom.Infrastructure.Host != nil {
				hostCfg = p.Custom.Infrastructure.Host
			}

			paths, err := host.GetPaths(hostCfg)
			if err != nil {
				return nil, fmt.Errorf("failed to determine paths: %w", err)
			}

			certDir := paths.CertDir("envoy-gateway")
			certPath = filepath.Join(certDir, "tls.crt")
			keyPath = filepath.Join(certDir, "tls.key")
			caPath = filepath.Join(certDir, "ca.crt")
		default:
			return nil, fmt.Errorf("no valid tls certificates")
		}
	}

	tlsConfig, err := crypto.LoadTLSConfig(certPath, keyPath, caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create tls config: %w", err)
	}
	return tlsConfig, err
}
