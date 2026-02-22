package conf

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/proxy/reflex"
	"google.golang.org/protobuf/proto"
)

// test Inbound Config Parser

func TestReflexInboundConfigBuild(t *testing.T) {
	// full config test
	t.Run("Full Config", func(t *testing.T) {
		jsonStr := `{
			"clients": [
				{
					"id": "27848739-7e62-4138-9fd3-098a63964b6b",
					"policy": "default"
				}
			],
			"fallback": {
				"dest": 80
			}
		}`

		var config ReflexInboundConfig
		if err := json.Unmarshal([]byte(jsonStr), &config); err != nil {
			t.Fatal("Failed to unmarshal JSON:", err)
		}

		result, err := config.Build()
		if err != nil {
			t.Fatal("Build failed:", err)
		}

		reflexConfig, ok := result.(*reflex.InboundConfig)
		if !ok {
			t.Fatal("Result is not *reflex.InboundConfig")
		}

		//  check clients
		if len(reflexConfig.Clients) != 1 {
			t.Errorf("Expected 1 client, got %d", len(reflexConfig.Clients))
		}
		if reflexConfig.Clients[0].Id != "27848739-7e62-4138-9fd3-098a63964b6b" {
			t.Errorf("Wrong client ID: %s", reflexConfig.Clients[0].Id)
		}
		if reflexConfig.Clients[0].Policy != "default" {
			t.Errorf("Wrong policy: %s", reflexConfig.Clients[0].Policy)
		}

		// check fallback
		if reflexConfig.Fallback == nil {
			t.Fatal("Fallback is nil")
		}
		if reflexConfig.Fallback.Dest != 80 {
			t.Errorf("Wrong fallback dest: %d", reflexConfig.Fallback.Dest)
		}

	})

	// test multiple clients
	t.Run("Multiple Clients", func(t *testing.T) {
		jsonStr := `{
			"clients": [
				{
					"id": "550e8400-e29b-41d4-a716-446655440000",
					"policy": "default"
				},
				{
					"id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
					"policy": "premium"
				}
			]
		}`

		var config ReflexInboundConfig
		if err := json.Unmarshal([]byte(jsonStr), &config); err != nil {
			t.Fatal("Failed to unmarshal JSON:", err)
		}

		result, err := config.Build()
		if err != nil {
			t.Fatal("Build failed:", err)
		}

		reflexConfig := result.(*reflex.InboundConfig)

		if len(reflexConfig.Clients) != 2 {
			t.Fatalf("Expected 2 clients, got %d", len(reflexConfig.Clients))
		}

		if reflexConfig.Clients[0].Id != "550e8400-e29b-41d4-a716-446655440000" {
			t.Error("Wrong first client ID")
		}
		if reflexConfig.Clients[1].Id != "6ba7b810-9dad-11d1-80b4-00c04fd430c8" {
			t.Error("Wrong second client ID")
		}
	})

	// test without fallback
	t.Run("No Fallback", func(t *testing.T) {
		jsonStr := `{
			"clients": [
				{
					"id": "27848739-7e62-4138-9fd3-098a63964b6b",
					"policy": "default"
				}
			]
		}`

		var config ReflexInboundConfig
		if err := json.Unmarshal([]byte(jsonStr), &config); err != nil {
			t.Fatal("Failed to unmarshal JSON:", err)
		}

		result, err := config.Build()
		if err != nil {
			t.Fatal("Build failed:", err)
		}

		reflexConfig := result.(*reflex.InboundConfig)

		if reflexConfig.Fallback != nil {
			t.Error("Fallback should be nil")
		}

	})

	//  test with empty clients
	t.Run("Empty Clients", func(t *testing.T) {
		jsonStr := `{
			"clients": []
		}`

		var config ReflexInboundConfig
		if err := json.Unmarshal([]byte(jsonStr), &config); err != nil {
			t.Fatal("Failed to unmarshal JSON:", err)
		}

		result, err := config.Build()
		if err != nil {
			t.Fatal("Build failed:", err)
		}

		reflexConfig := result.(*reflex.InboundConfig)

		if len(reflexConfig.Clients) != 0 {
			t.Errorf("Expected 0 clients, got %d", len(reflexConfig.Clients))
		}
	})
}

// test Outbound Config Parser

func TestReflexOutboundConfigBuild(t *testing.T) {
	// full config test
	t.Run("Full Config", func(t *testing.T) {
		jsonStr := `{
			"address": "example.com",
			"port": 443,
			"id": "27848739-7e62-4138-9fd3-098a63964b6b"
		}`

		var config ReflexOutboundConfig
		if err := json.Unmarshal([]byte(jsonStr), &config); err != nil {
			t.Fatal("Failed to unmarshal JSON:", err)
		}

		result, err := config.Build()
		if err != nil {
			t.Fatal("Build failed:", err)
		}

		reflexConfig, ok := result.(*reflex.OutboundConfig)
		if !ok {
			t.Fatal("Result is not *reflex.OutboundConfig")
		}

		if reflexConfig.Address != "example.com" {
			t.Errorf("Wrong address: %s", reflexConfig.Address)
		}
		if reflexConfig.Port != 443 {
			t.Errorf("Wrong port: %d", reflexConfig.Port)
		}
		if reflexConfig.Id != "27848739-7e62-4138-9fd3-098a63964b6b" {
			t.Errorf("Wrong ID: %s", reflexConfig.Id)
		}

	})

	// test with IP
	t.Run("IP Address", func(t *testing.T) {
		jsonStr := `{
			"address": "1.2.3.4",
			"port": 8443,
			"id": "550e8400-e29b-41d4-a716-446655440000"
		}`

		var config ReflexOutboundConfig
		if err := json.Unmarshal([]byte(jsonStr), &config); err != nil {
			t.Fatal("Failed to unmarshal JSON:", err)
		}

		result, err := config.Build()
		if err != nil {
			t.Fatal("Build failed:", err)
		}

		reflexConfig := result.(*reflex.OutboundConfig)

		if reflexConfig.Address != "1.2.3.4" {
			t.Errorf("Wrong address: %s", reflexConfig.Address)
		}
		if reflexConfig.Port != 8443 {
			t.Errorf("Wrong port: %d", reflexConfig.Port)
		}
	})

}

// test Proto Equality
func TestReflexProtoEquality(t *testing.T) {
	jsonStr := `{
		"clients": [
			{
				"id": "test-uuid",
				"policy": "test-policy"
			}
		],
		"fallback": {
			"dest": 80
		}
	}`

	var config ReflexInboundConfig
	json.Unmarshal([]byte(jsonStr), &config)

	result1, _ := config.Build()
	result2, _ := config.Build()

	if !proto.Equal(result1, result2) {
		t.Error("Two builds of same config should be equal")
	}
}
