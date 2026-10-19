package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"example.invalid/dedicatedcloud/backend/internal/auth"
	"example.invalid/dedicatedcloud/backend/internal/schedule"
	"example.invalid/dedicatedcloud/backend/internal/simhost"
)

func (r *crig) setSchedule(b *browser, vm, key string, params string) reply {
	return r.post(b, `{"type":"schedule_set","kind":"VM","id":"`+vm+`","idempotency_key":"`+key+`","params":`+params+`}`)
}

const goodSchedule = `{"every_hours":6,"keep_local":3,"keep_offsite":0,"downtime_acknowledged":true}`

func (r *crig) vmWith(admin *browser, name string) {
	r.t.Helper()
	r.await(admin, opID(r.t, r.post(admin, r.createBody(name, r.key, nil))), "succeeded")
}

type vmSched struct {
	Desired struct {
		BackupSchedule *struct {
			EveryHours           *int    `json:"every_hours"`
			At                   *string `json:"at"`
			KeepLocal            int     `json:"keep_local"`
			KeepOffsite          int     `json:"keep_offsite"`
			TargetID             *string `json:"target_id"`
			DowntimeAcknowledged bool    `json:"downtime_acknowledged"`
		} `json:"backup_schedule"`
	} `json:"desired"`
	Observed struct {
		Backup struct {
			NextRunAt *string `json:"next_run_at"`
			LastRun   *struct {
				At     string `json:"at"`
				Result string `json:"result"`
			} `json:"last_run"`
		} `json:"backup"`
	} `json:"observed"`
	Allowed []string `json:"allowed_actions"`
}

func readVMSched(t *testing.T, b *browser, vm string) vmSched {
	t.Helper()
	var v vmSched
	rep := b.do("GET", "/api/v1/vms/"+vm, "", nil)
	if err := json.Unmarshal(rep.body, &v); err != nil || rep.status != 200 {
		t.Fatalf("%d %v %s", rep.status, err, rep.body)
	}
	return v
}

func TestAnOperatorSchedulesAndClearsABackupWindow(t *testing.T) {
	r := newCRig(t, true)
	admin := signedIn(t, r.env)
	r.vmWith(admin, "web-1")
	o := r.asRole("olly", auth.RoleOperator)
	if v := readVMSched(t, o, "web-1"); v.Desired.BackupSchedule != nil || v.Observed.Backup.NextRunAt != nil || !hasAction(v.Allowed, "set_schedule") || hasAction(v.Allowed, "clear_schedule") {
		t.Fatalf("no schedule yet, one may be set: %+v", v)
	}
	rep := r.setSchedule(o, "web-1", "sch-1", goodSchedule)
	if rep.status != 202 {
		t.Fatalf("%d %s", rep.status, rep.body)
	}
	r.await(o, opID(t, rep), "succeeded")
	v := readVMSched(t, o, "web-1")
	s := v.Desired.BackupSchedule
	if s == nil || s.EveryHours == nil || *s.EveryHours != 6 || s.At != nil || s.KeepLocal != 3 || s.TargetID != nil || !s.DowntimeAcknowledged || v.Observed.Backup.NextRunAt == nil || v.Observed.Backup.LastRun != nil {
		t.Fatalf("%+v", v)
	}
	if !hasAction(v.Allowed, "clear_schedule") || !hasAction(v.Allowed, "set_schedule") {
		t.Fatalf("allowed %v", v.Allowed)
	}
	// replaying the same request answers with the same operation
	if again := r.setSchedule(o, "web-1", "sch-1", goodSchedule); again.status != 202 || opID(t, again) != opID(t, rep) {
		t.Fatalf("%d %s", again.status, again.body)
	}
	// changing it: a daily window
	rep = r.setSchedule(o, "web-1", "sch-2", `{"at":"02:30","keep_local":5,"keep_offsite":0,"downtime_acknowledged":true}`)
	r.await(o, opID(t, rep), "succeeded")
	if s := readVMSched(t, o, "web-1").Desired.BackupSchedule; s == nil || s.At == nil || *s.At != "02:30" || s.EveryHours != nil || s.KeepLocal != 5 {
		t.Fatalf("%+v", s)
	}
	clr := r.post(o, `{"type":"schedule_clear","kind":"VM","id":"web-1","idempotency_key":"sch-3"}`)
	if clr.status != 202 {
		t.Fatalf("%d %s", clr.status, clr.body)
	}
	r.await(o, opID(t, clr), "succeeded")
	if v := readVMSched(t, o, "web-1"); v.Desired.BackupSchedule != nil || hasAction(v.Allowed, "clear_schedule") {
		t.Fatalf("%+v", v)
	}
}

func hasAction(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func TestAScheduleRequiresTheDowntimeAcknowledgementAndSaneValues(t *testing.T) {
	r := newCRig(t, true)
	admin := signedIn(t, r.env)
	r.vmWith(admin, "web-1")
	bad := map[string]string{
		"not acknowledged":   `{"every_hours":6,"keep_local":3,"keep_offsite":0,"downtime_acknowledged":false}`,
		"no acknowledgement": `{"every_hours":6,"keep_local":3,"keep_offsite":0}`,
		"both cadences":      `{"every_hours":6,"at":"02:30","keep_local":3,"keep_offsite":0,"downtime_acknowledged":true}`,
		"no cadence":         `{"keep_local":3,"keep_offsite":0,"downtime_acknowledged":true}`,
		"zero retention":     `{"every_hours":6,"keep_local":0,"keep_offsite":0,"downtime_acknowledged":true}`,
		"retention too big":  `{"every_hours":6,"keep_local":31,"keep_offsite":0,"downtime_acknowledged":true}`,
		"hours too big":      `{"every_hours":169,"keep_local":3,"keep_offsite":0,"downtime_acknowledged":true}`,
		"bad time":           `{"at":"25:00","keep_local":3,"keep_offsite":0,"downtime_acknowledged":true}`,
		"time without zero":  `{"at":"2:30","keep_local":3,"keep_offsite":0,"downtime_acknowledged":true}`,
		"offsite no target":  `{"every_hours":6,"keep_local":3,"keep_offsite":2,"downtime_acknowledged":true}`,
		"target no offsite":  `{"every_hours":6,"keep_local":3,"keep_offsite":0,"target_id":"usb-disk","downtime_acknowledged":true}`,
		"undeclared target":  `{"every_hours":6,"keep_local":3,"keep_offsite":2,"target_id":"usb-disk","downtime_acknowledged":true}`,
		"foreign field":      `{"every_hours":6,"keep_local":3,"keep_offsite":0,"downtime_acknowledged":true,"disk_gib":5}`,
	}
	for name, p := range bad {
		rep := r.setSchedule(admin, "web-1", "k-"+strings.ReplaceAll(name, " ", "-"), p)
		if rep.status != 400 {
			t.Errorf("%s: %d %s", name, rep.status, rep.body)
		}
	}
	if rep := r.post(admin, `{"type":"schedule_set","kind":"VM","id":"web-1","idempotency_key":"k-nop"}`); rep.status != 400 {
		t.Errorf("no params: %d", rep.status)
	}
	if rep := r.post(admin, `{"type":"schedule_clear","kind":"VM","id":"web-1","idempotency_key":"k-clr","params":`+goodSchedule+`}`); rep.status != 400 {
		t.Errorf("clear with params: %d", rep.status)
	}
	if all, _ := r.sstore.All(context.Background()); len(all) != 0 {
		t.Fatalf("nothing may have been stored: %+v", all)
	}
}

func TestAScheduleIsRefusedForAViewerAForeignVMAndAMissingOne(t *testing.T) {
	r := newCRig(t, true)
	admin := signedIn(t, r.env)
	r.vmWith(admin, "web-1")
	v := r.asRole("vera", auth.RoleViewer)
	if rep := r.setSchedule(v, "web-1", "v-1", goodSchedule); rep.status != 403 {
		t.Errorf("viewer: %d", rep.status)
	}
	if got := readVMSched(t, v, "web-1"); hasAction(got.Allowed, "set_schedule") {
		t.Errorf("a viewer is not offered it: %v", got.Allowed)
	}
	if rep := r.setSchedule(admin, "nope", "m-1", goodSchedule); rep.status != 404 {
		t.Errorf("missing VM: %d %s", rep.status, rep.body)
	}
	_ = r.sim.Add("alien", simhost.Domain{UUID: "9a9a9a9a-2222-4333-8444-5555555555ab", Running: true, VCPUs: 1, MemoryMiB: 64})
	if rep := r.setSchedule(admin, "alien", "f-1", goodSchedule); rep.status != 422 {
		t.Errorf("foreign VM must be refused: %d %s", rep.status, rep.body)
	}
	if all, _ := r.sstore.All(context.Background()); len(all) != 0 {
		t.Fatalf("%+v", all)
	}
}

var _ = schedule.ResultOK
