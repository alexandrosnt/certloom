package agent

import (
	"testing"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/cloudobs"
)

func TestCloudOnlyAgent(t *testing.T) {
	c := &Config{Cloud: &cloudobs.Config{AWS: []cloudobs.AWSAccountConfig{{Name: "a", Regions: []string{"eu-west-1"}}}}}
	if !c.taskAllowed(agentproto.TaskInventoryScan) || c.taskAllowed(agentproto.TaskIssue) {
		t.Error("a cloud-only agent must accept only inventory tasks")
	}
	if c.inventoryInterval() != cloudobs.DefaultInterval {
		t.Errorf("interval %d", c.inventoryInterval())
	}
}
