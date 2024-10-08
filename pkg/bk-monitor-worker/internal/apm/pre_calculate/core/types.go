// Tencent is pleased to support the open source community by making
// 蓝鲸智云 - 监控平台 (BlueKing - Monitor) available.
// Copyright (C) 2022 THL A29 Limited, a Tencent company. All rights reserved.
// Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://opensource.org/licenses/MIT
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.

package core

import (
	"fmt"
	"strings"
)

const (
	// SpanMaxSize Maximum of analyses
	SpanMaxSize = 10000
)

// SpanCategory Classification of span
type SpanCategory string

const (
	// CategoryHttp category: Http
	CategoryHttp SpanCategory = "http"
	// CategoryRpc category: Rpc
	CategoryRpc SpanCategory = "rpc"
	// CategoryDb category: Db
	CategoryDb SpanCategory = "db"
	// CategoryMessaging category: Message
	CategoryMessaging SpanCategory = "messaging"
	// CategoryAsyncBackend category: AsyncBackend
	CategoryAsyncBackend SpanCategory = "async_backend"
	// CategoryOther category: Other
	CategoryOther SpanCategory = "other"
)

// SpanStatusCode field from status.code
type SpanStatusCode int

const (
	// StatusCodeUnset status.code=0
	StatusCodeUnset SpanStatusCode = iota
	// StatusCodeOk status.code=1
	StatusCodeOk
	// StatusCodeError status.code=2
	StatusCodeError
)

// SpanKind field from kind
type SpanKind int

const (
	// KindUnspecified span kind: unspecified
	KindUnspecified SpanKind = 0
	// KindInterval span kind: interval
	KindInterval SpanKind = 1
	// KindServer span kind: server
	KindServer SpanKind = 2
	// KindClient span kind: client
	KindClient SpanKind = 3
	// KindProducer span kind: producer
	KindProducer SpanKind = 4
	// KindConsumer span kind: consumer
	KindConsumer SpanKind = 5
)

// SpanKindCategory kind to category Mapping
type SpanKindCategory string

const (
	// KindCategoryUnspecified span kind: 0 -> unspecified
	KindCategoryUnspecified SpanKindCategory = "unspecified"
	// KindCategoryInterval span kind: 1 -> unspecified
	KindCategoryInterval SpanKindCategory = "interval"
	// KindCategorySync span kind: 2/3 -> sync
	KindCategorySync SpanKindCategory = "sync"
	// KindCategoryAsync span kind 4/5 -> async
	KindCategoryAsync SpanKindCategory = "async"
)

// ToKindCategory span.kind convert to category by SpanKindCategory
func (s SpanKind) ToKindCategory() SpanKindCategory {
	switch s {
	case KindUnspecified:
		return KindCategoryUnspecified
	case KindInterval:
		return KindCategoryInterval
	case KindServer:
		return KindCategorySync
	case KindClient:
		return KindCategorySync
	case KindProducer:
		return KindCategoryAsync
	case KindConsumer:
		return KindCategoryAsync
	default:
		return ""
	}
}

// IsCalledKind determine whether span.kind is the called party or not
func (s SpanKind) IsCalledKind() bool {
	return s == KindServer || s == KindConsumer
}

// CommonField span standard field enum.
type CommonField struct {
	Source  FiledSource
	Key     string
	FullKey string
}

// DisplayKey field name in span origin data
func (c *CommonField) DisplayKey() string {
	var builder strings.Builder
	switch c.Source {
	case SourceAttributes:
		builder.WriteString("attributes.")
		builder.WriteString(c.Key)
		r := builder.String()
		builder.Reset()
		return r
	case SourceResource:
		builder.WriteString("resource.")
		builder.WriteString(c.Key)
		r := builder.String()
		builder.Reset()
		return r
	default:
		return c.Key
	}
}

// Contain whether the field is in Mapping
func (c *CommonField) Contain(collections map[string]string) bool {
	_, exist := collections[c.FullKey]
	return exist
}

// ToDimensionKey convert to metric dimension key
func (c *CommonField) ToDimensionKey() string {
	return strings.ReplaceAll(c.Key, ".", "_")
}

// FiledSource source of filed
type FiledSource string

const (
	// SourceResource source: span.resource field
	SourceResource FiledSource = "resource"
	// SourceAttributes source: span.attributes field
	SourceAttributes FiledSource = "attributes"
	// SourceOuter source from outer(span_name, kind, etc..)
	SourceOuter FiledSource = "outer"
)

func toAttributes(n string) string {
	return fmt.Sprintf("%s.%s", SourceAttributes, n)
}

func toResource(n string) string {
	return fmt.Sprintf("%s.%s", SourceResource, n)
}

var (
	HttpHostField    = CommonField{SourceAttributes, "http.host", toAttributes("http.host")}
	HttpUrlField     = CommonField{SourceAttributes, "http.url", toAttributes("http.url")}
	NetPeerNameField = CommonField{
		SourceAttributes, "net.peer.name", toAttributes("net.peer.name"),
	}
	NetPeerIpField = CommonField{
		SourceAttributes, "net.peer.ip", toAttributes("net.peer.ip"),
	}
	NetPeerPortField = CommonField{
		SourceAttributes, "net.peer.port", toAttributes("net.peer.port"),
	}
	ServerAddressField = CommonField{
		SourceAttributes, "server.address", toAttributes("server.address"),
	}
	PeerServiceField = CommonField{
		SourceAttributes, "peer.service", toAttributes("peer.service"),
	}
	HttpSchemeField = CommonField{
		SourceAttributes, "http.scheme", toAttributes("http.scheme"),
	}
	HttpFlavorField = CommonField{
		SourceAttributes, "http.flavor", toAttributes("http.flavor"),
	}
	HttpMethodField = CommonField{
		SourceAttributes, "http.method",
		toAttributes("http.method"),
	}
	HttpStatusCodeField = CommonField{
		SourceAttributes, "http.status_code",
		toAttributes("http.status_code"),
	}

	RpcMethodField = CommonField{
		SourceAttributes, "rpc.method", toAttributes("rpc.method"),
	}
	RpcServiceField = CommonField{
		SourceAttributes, "rpc.service", toAttributes("rpc.service"),
	}
	RpcSystemField = CommonField{
		SourceAttributes, "rpc.system", toAttributes("rpc.system"),
	}
	RpcGrpcStatusCode = CommonField{
		SourceAttributes, "rpc.grpc.status_code",
		toAttributes("rpc.grpc.status_code"),
	}

	DbNameField = CommonField{
		SourceAttributes, "db.name", toAttributes("db.name"),
	}
	DbOperationField = CommonField{
		SourceAttributes, "db.operation", toAttributes("db.operation"),
	}
	DbSystemField = CommonField{
		SourceAttributes, "db.system", toAttributes("db.system"),
	}
	DbStatementField = CommonField{
		SourceAttributes, "db.statement",
		toAttributes("db.statement"),
	}
	DbTypeField = CommonField{
		SourceAttributes, "db.type", toAttributes("db.type"),
	}
	DbInstanceField = CommonField{
		SourceAttributes, "db.instance", toAttributes("db.instance"),
	}

	MessagingRabbitmqRoutingKeyField = CommonField{
		SourceAttributes, "messaging.rabbitmq.routing_key",
		toAttributes("messaging.rabbitmq.routing_key"),
	}
	MessagingKafkaKeyField = CommonField{
		SourceAttributes, "messaging.kafka.message_key",
		toAttributes("messaging.kafka.message_key"),
	}
	MessagingRocketmqKeyField = CommonField{
		SourceAttributes, "messaging.rocketmq.message_keys",
		toAttributes("messaging.rocketmq.message_keys"),
	}

	MessagingSystemField = CommonField{
		SourceAttributes, "messaging.system",
		toAttributes("messaging.system"),
	}
	MessagingDestinationField = CommonField{
		SourceAttributes, "messaging.destination",
		toAttributes("messaging.destination"),
	}
	MessagingDestinationKindField = CommonField{
		SourceAttributes, "messaging.destination_kind",
		toAttributes("messaging.destination_kind"),
	}
	CeleryActionField = CommonField{
		SourceAttributes, "celery.action", toAttributes("celery.action"),
	}
	CeleryTaskNameField = CommonField{
		SourceAttributes, "celery.task_name",
		toAttributes("celery.task_name"),
	}

	ServiceNameField = CommonField{
		SourceResource, "service.name", toResource("service.name"),
	}
	ServiceVersionField = CommonField{
		SourceResource, "service.version",
		toResource("service.version"),
	}
	TelemetrySdkLanguageField = CommonField{
		SourceResource, "telemetry.sdk.language",
		toResource("telemetry.sdk.language"),
	}
	TelemetrySdkNameField = CommonField{
		SourceResource, "telemetry.sdk.name",
		toResource("telemetry.sdk.name"),
	}
	TelemetrySdkVersionField = CommonField{
		SourceResource, "telemetry.sdk.version",
		toResource("telemetry.sdk.version"),
	}
	ServiceNamespaceField = CommonField{
		SourceResource, "service.namespace", toResource("service.namespace"),
	}
	ServiceInstanceIdField = CommonField{
		SourceResource, "service.instance.id",
		toResource("service.instance.id"),
	}
	NetHostIpField = CommonField{
		SourceResource, "net.host.ip", toResource("net.host.ip"),
	}
	K8sBcsClusterId = CommonField{
		SourceResource, "k8s.bcs.cluster.id", toResource("k8s.bcs.cluster.id"),
	}
	K8sNamespace = CommonField{
		SourceResource, "k8s.namespace.name", toResource("k8s.namespace.name"),
	}
	K8sPodIp = CommonField{
		SourceResource, "k8s.pod.ip", toResource("k8s.pod.ip"),
	}
	K8sPodName = CommonField{
		SourceResource, "k8s.pod.name", toResource("k8s.pod.name"),
	}
	HostIpField = CommonField{
		SourceResource, "host.ip", toResource("host.ip"),
	}
	NetHostPortField = CommonField{
		SourceResource, "net.host.port", toResource("net.host.port"),
	}
	NetHostnameField = CommonField{
		SourceResource, "net.host.name", toResource("net.host.name"),
	}
	BkInstanceIdField = CommonField{
		SourceResource, "bk.instance.id",
		toResource("bk.instance.id"),
	}
	KindField     = CommonField{SourceOuter, "kind", "kind"}
	SpanNameField = CommonField{SourceOuter, "span_name", "span_name"}
)

var StandardFields = []CommonField{
	HttpHostField,
	HttpUrlField,
	NetPeerNameField,
	NetPeerIpField,
	NetPeerPortField,
	ServerAddressField,
	PeerServiceField,
	HttpSchemeField,
	HttpFlavorField,
	HttpMethodField,
	HttpStatusCodeField,

	RpcMethodField,
	RpcServiceField,
	RpcSystemField,
	RpcGrpcStatusCode,

	DbNameField,
	DbOperationField,
	DbSystemField,
	DbStatementField,
	DbInstanceField,

	MessagingSystemField,
	MessagingDestinationField,
	MessagingDestinationKindField,
	CeleryActionField,
	CeleryTaskNameField,

	ServiceNameField,
	ServiceVersionField,
	TelemetrySdkLanguageField,
	TelemetrySdkNameField,
	TelemetrySdkVersionField,
	ServiceNamespaceField,
	ServiceInstanceIdField,
	NetHostIpField,
	HostIpField,
	K8sBcsClusterId,
	K8sNamespace,
	K8sPodIp,
	K8sPodName,
	NetHostPortField,
	NetHostnameField,
	BkInstanceIdField,
	KindField,
	SpanNameField,
}

type CategoryPredicate struct {
	Category     SpanCategory
	AnyFields    []CommonField
	OptionFields []CommonField
}

var CategoryPredicateFields = []CategoryPredicate{
	{
		Category: CategoryMessaging,
		AnyFields: []CommonField{
			MessagingDestinationField,
			MessagingSystemField,
			MessagingDestinationKindField,
		},
		OptionFields: []CommonField{
			MessagingRabbitmqRoutingKeyField,
			MessagingKafkaKeyField,
			MessagingRocketmqKeyField,
		},
	},
	{
		Category: CategoryAsyncBackend,
		AnyFields: []CommonField{
			MessagingDestinationField,
			MessagingDestinationKindField,
			MessagingSystemField,
			CeleryTaskNameField,
			CeleryActionField,
		},
	},
	{
		Category: CategoryDb,
		AnyFields: []CommonField{
			DbNameField,
			DbOperationField,
			DbSystemField,
			DbStatementField,
			DbTypeField,
			DbInstanceField,
		},
	},
	{
		Category: CategoryRpc,
		AnyFields: []CommonField{
			RpcMethodField,
			RpcServiceField,
			RpcSystemField,
			RpcGrpcStatusCode,
		},
	},
	{
		Category: CategoryHttp,
		AnyFields: []CommonField{
			HttpHostField,
			HttpUrlField,
			NetPeerNameField,
			PeerServiceField,
			HttpSchemeField,
			HttpFlavorField,
			HttpMethodField,
			HttpStatusCodeField,
		},
	},
}
