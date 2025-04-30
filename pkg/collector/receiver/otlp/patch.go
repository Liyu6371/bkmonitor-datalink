package otlp

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/TencentBlueKing/bkmonitor-datalink/pkg/utils/logger"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

// patch.go 用于增强 OTLP 编码器的功能
// 主要是为了支持新版本探针上报字段 与 旧版本探针不一致的问题

// TracePatch trance 类型数据补丁
func TracePatch(trace ptrace.Traces) {
	resourceSpans := trace.ResourceSpans()
	for i := 0; i < resourceSpans.Len(); i++ {
		scopeSpans := resourceSpans.At(i).ScopeSpans()
		for j := 0; j < scopeSpans.Len(); j++ {
			spans := scopeSpans.At(j).Spans()
			for k := 0; k < spans.Len(); k++ {
				span := spans.At(k)
				spanType := decideSpanType(span.Attributes())
				logger.Errorf("span traceId is %s", span.TraceID().HexString())
				logger.Errorf("span spanId is %s", span.SpanID().HexString())
				logger.Errorf("spanType is %s", spanType)
				logger.Errorf("span kind is %d", span.Kind())
				switch spanType {
				case "http":
					logger.Errorf("Before http span name: %s", span.Name())
					httpSpanNamePatch(span, span.Kind())
					logger.Errorf("After http span name: %s", span.Name())
					a, _ := json.Marshal(span.Attributes().AsRaw())
					logger.Errorf("Before http span attr: %s", string(a))
					httpSpanPatch(span.Attributes(), span.Kind())
					b, _ := json.Marshal(span.Attributes().AsRaw())
					logger.Errorf("After http span attr: %s", string(b))
				case "db":
					a, _ := json.Marshal(span.Attributes().AsRaw())
					logger.Errorf("Before db span attr: %s", string(a))
					dbSpanPatch(span.Attributes(), span.Kind())
					b, _ := json.Marshal(span.Attributes().AsRaw())
					logger.Errorf("After db span attr: %s", string(b))
				case "messaging":
					a, _ := json.Marshal(span.Attributes().AsRaw())
					logger.Errorf("Before messaging span attr: %s", string(a))
					messagingSpanPatch(span.Attributes(), span.Kind())
					b, _ := json.Marshal(span.Attributes().AsRaw())
					logger.Errorf("After messaging span attr: %s", string(b))
				default:
					continue
				}
			}
		}
	}
}

// decideSpanType 通过 Span 的属性来决定 Span 的类型
// 目前支持的类型有 http, db, messaging
// 其他类型的 span 将返回 "skip"
func decideSpanType(attribute pcommon.Map) string {
	m := attribute.AsRaw()
	if isHttpSpan(m) {
		return "http"
	}
	if isDbSpan(m) {
		return "db"
	}
	if isMessagingSpan(m) {
		return "messaging"
	}
	return "skip"
}

// isHttpSpan 判断是否是 http 类型的 span
// 从目前OT数据来看，有些 HTTP 类型的 span 不会存在明确的能够分辨类型的字段，所以添加多个关键 attr 检测
func isHttpSpan(attrMap map[string]interface{}) bool {
	checkKeys := []string{
		"http.method", "url.scheme", "http.scheme", "url.full",
		"http.request.method", "http.response.status_code",
	}
	return check(attrMap, checkKeys)
}

func isDbSpan(attrMap map[string]interface{}) bool {
	checkKeys := []string{
		"db.system", "db.operation", "db.name", "db.statement",
		"db.user",
	}
	return check(attrMap, checkKeys)
}

func isMessagingSpan(attrMap map[string]interface{}) bool {
	checkKeys := []string{
		"messaging.system", "messaging.operation", "messaging.destination.name",
		"messaging.client_id", "messaging.kafka.message.offset", "messaging.destination.partition.id",
	}
	return check(attrMap, checkKeys)
}

func check(attrMap map[string]interface{}, checkKeys []string) bool {
	for _, k := range checkKeys {
		if _, ok := attrMap[k]; ok {
			return true
		}
	}
	return false
}

// httpSpanPatch 处理 http 类型的 span 补丁
func httpSpanPatch(attribute pcommon.Map, kind ptrace.SpanKind) {
	httpReflectMap := map[string][]string{
		"url.path":                  {"http.target"},
		"http.request.method":       {"http.method"},
		"http.response.status_code": {"http.status_code"},
		"url.full":                  {"http.url"},
		"url.scheme":                {"http.scheme"},
		"client.address":            {"http.client_ip"},
		"network.peer.address":      {"net.sock.peer.addr", "net.sock.peer.name"},
		"network.peer.port":         {"net.sock.peer.port"},
		"network.local.address":     {"net.sock.host.addr"},
		"network.local.port":        {"net.sock.host.port"},
	}
	transformAttr(httpReflectMap, attribute)
	//  kind = 2
	if kind == ptrace.SpanKindServer {
		var (
			clientAddr string
			serverAddr string
			clientPort int
			serverPort int
		)
		if v, ok := attribute.Get("client.address"); ok {
			attribute.InsertString("net.peer.ip", v.AsString())
			clientAddr = v.AsString()
		}
		if v, ok := attribute.Get("client.port"); ok {
			attribute.InsertInt("net.peer.port", v.IntVal())
			clientPort = int(v.IntVal())
		}
		if clientAddr != "" && clientPort != 0 {
			attribute.InsertString("net.peer.name", fmt.Sprintf("%s:%d", clientAddr, clientPort))

		}

		if v, ok := attribute.Get("server.address"); ok {
			attribute.InsertString("net.host.ip", v.AsString())
			serverAddr = v.AsString()
		}
		if v, ok := attribute.Get("server.port"); ok {
			attribute.InsertInt("net.host.port", v.IntVal())
			serverPort = int(v.IntVal())
		}
		if serverAddr != "" && serverPort != 0 {
			attribute.InsertString("net.host.name", fmt.Sprintf("%s:%d", serverAddr, serverPort))
		}
	}

	//  kind = 3
	if kind == ptrace.SpanKindClient {
		var (
			clientAddr string
			serverAddr string
			clientPort int
			serverPort int
		)

		if v, ok := attribute.Get("server.address"); ok {
			attribute.InsertString("net.peer.ip", v.AsString())
			serverAddr = v.AsString()
		}
		if t, ok := attribute.Get("server.port"); ok {
			attribute.InsertInt("net.peer.port", t.IntVal())
			serverPort = int(t.IntVal())
		}
		if serverAddr != "" && serverPort != 0 {
			attribute.InsertString("net.peer.name", fmt.Sprintf("%s:%d", serverAddr, serverPort))
		}

		if v, ok := attribute.Get("client.address"); ok {
			attribute.InsertString("net.host.ip", v.AsString())
			clientAddr = v.AsString()
		}
		if v, ok := attribute.Get("client.port"); ok {
			attribute.InsertInt("net.host.port", v.IntVal())
			clientPort = int(v.IntVal())
		}
		if clientAddr != "" && clientPort != 0 {
			attribute.InsertString("net.host.name", fmt.Sprintf("%s:%d", clientAddr, clientPort))
		}
	}
}

// httpSpanNamePatch 处理 http 类型的 spanName 补丁
func httpSpanNamePatch(span ptrace.Span, kind ptrace.SpanKind) {
	// 目前只处理 span kind = 3 的情况
	if kind != ptrace.SpanKindClient {
		return
	}
	spAttr := span.Attributes()
	v, ok := spAttr.Get("url.full")
	if !ok {
		logger.Debugf("httpSpanNamePatch url.full not found")
		return
	}
	urlFull := v.AsString()
	u, err := url.Parse(urlFull)
	if err != nil {
		logger.Debugf("httpSpanNamePatch url parse error %s", err)
		return
	}
	if u.Path != "" {
		span.SetName(u.Path)
		return
	}
}

func dbSpanPatch(attribute pcommon.Map, kind ptrace.SpanKind) {
	// 需要特殊处理的 key
	dbSpecialKey := "db.operation.parameter"
	m := attribute.AsRaw()
	values := make([]string, 0)

	for k := range m {
		if strings.HasPrefix(k, dbSpecialKey) {
			val, ok := attribute.Get(k)
			if ok {
				logger.Debugf("dbSpanPatch key is %s, val is %s", k, val.StringVal())
				values = append(values, val.StringVal())
			}
		}
	}

	if len(values) > 0 {
		logger.Debugf("dbSpanPatch values is %s", values)
		if bytesData, err := json.Marshal(values); err == nil {
			attribute.InsertMBytes("db.sql.parameters", bytesData)
		} else {
			logger.Errorf("dbSpanPatch marshal error %s", err)
		}
	}

	dbReflectMap := map[string][]string{
		"db.system.name":       {"db.system"},
		"db.namespace":         {"db.name"},
		"db.query.text":        {"db.statement"},
		"db.operation.name":    {"db.operation"},
		"db.collection.name":   {"db.sql.table"},
		"network.peer.address": {"net.sock.peer.addr", "server.address"},
		"network.peer.port":    {"net.sock.peer.port", "server.port"},
	}
	transformAttr(dbReflectMap, attribute)

	if kind == ptrace.SpanKindClient {
		var (
			serverAddr string
			clientAddr string
			serverPort int
			clientPort int
		)

		if v, ok := attribute.Get("server.address"); ok {
			attribute.InsertString("net.peer.ip", v.AsString())
			serverAddr = v.AsString()
		}

		if v, ok := attribute.Get("server.port"); ok {
			attribute.InsertInt("net.peer.port", v.IntVal())
			serverPort = int(v.IntVal())
		}
		if serverAddr != "" && serverPort != 0 {
			attribute.InsertString("net.peer.name", fmt.Sprintf("%s:%d", serverAddr, serverPort))
		}

		if v, ok := attribute.Get("client.address"); ok {
			attribute.InsertString("net.host.ip", v.AsString())
			clientAddr = v.AsString()
		}

		if v, ok := attribute.Get("client.port"); ok {
			attribute.InsertInt("net.host.port", v.IntVal())
			clientPort = int(v.IntVal())
		}
		if clientAddr != "" && clientPort != 0 {
			attribute.InsertString("net.host.name", fmt.Sprintf("%s:%d", clientAddr, clientPort))
		}
	}
}

func messagingSpanPatch(attribute pcommon.Map, kind ptrace.SpanKind) {
	messagingReflectMap := map[string][]string{
		"messaging.destination.name": {"topic"},
	}
	transformAttr(messagingReflectMap, attribute)
	if v, ok := attribute.Get("network.peer.address"); ok {
		attribute.InsertString("net.sock.peer.addr", v.AsString())
		attribute.InsertString("net.sock.peer.port", v.AsString())
	}
	if v, ok := attribute.Get("network.peer.port"); ok {
		attribute.UpdateInt("net.sock.peer.port", v.IntVal())
	}

	if kind == ptrace.SpanKindClient {
		if v, ok := attribute.Get("server.address"); ok {
			attribute.InsertString("net.peer.name", v.AsString())
			attribute.InsertString("net.peer.port", v.AsString())
		}
		if v, ok := attribute.Get("server.port"); ok {
			attribute.UpdateInt("net.peer.port", v.IntVal())
		}
	}
}

func transformAttr(reflectMap map[string][]string, attribute pcommon.Map) {
	for oldKey, newKeys := range reflectMap {
		if v, ok := attribute.Get(oldKey); ok {
			switch v.Type() {
			case pcommon.ValueTypeString:
				for _, newKey := range newKeys {
					attribute.InsertString(newKey, v.StringVal())
				}
			case pcommon.ValueTypeInt:
				for _, newKey := range newKeys {
					attribute.InsertInt(newKey, v.IntVal())
				}
			case pcommon.ValueTypeDouble:
				for _, newKey := range newKeys {
					attribute.InsertDouble(newKey, v.DoubleVal())
				}
			case pcommon.ValueTypeBool:
				for _, newKey := range newKeys {
					attribute.InsertBool(newKey, v.BoolVal())
				}
			default:
				// 其他类型暂不处理
				continue
			}
		}
	}
}
