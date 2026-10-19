// Words for alerts (DR-024 D2). The server sends a closed rule id and a bounded figure; everything a person reads is written here.
import type { Event } from "../api/schema";

export interface RuleText { title: string; detail: (e: Event) => string; todo: string }

const pct = (e: Event) => (e.value === null ? "" : `${e.value}`);

export const RULES: Record<string, RuleText> = {
  pool_free_low: { title: "Storage pool space is low", detail: (e) => (e.value === null ? "The storage pool is nearly full." : `${pct(e)}% of the storage pool is free.`),
    todo: "Delete virtual machines, snapshots or data volumes you no longer need, or add space under the pool." },
  backup_store_free_low: { title: "Backup store space is low", detail: (e) => (e.value === null ? "The backup store is nearly full." : `${pct(e)}% of the backup store's disk is free.`),
    todo: "Delete backups you no longer need, or add space under the backup directory. A backup that does not fit will fail." },
  host_memory_high: { title: "Host memory is nearly full", detail: (e) => (e.value === null ? "Host memory use is high." : `${pct(e)}% of the host's memory is in use.`),
    todo: "Stop virtual machines you do not need, or reduce their memory. A host that runs out of memory stops guests without warning." },
  vm_crashed: { title: "A virtual machine crashed", detail: () => "The hypervisor reports this machine as crashed.",
    todo: "Open the machine, look at its console output, then power it off and start it again." },
  vm_stopped_unexpectedly: { title: "A virtual machine stopped without being asked", detail: () => "It was running a moment ago and no request of yours stopped it.",
    todo: "Look at the console output and the host log for the reason, then start it again. A guest that shuts itself down is the usual cause." },
  operation_retries_exhausted: { title: "A request ran out of retries", detail: () => "Svavyom tried this several times and the host did not complete it.",
    todo: "Open Activity to see what was asked and why it failed. Cancel the request or fix the cause and ask again." },
  scheduled_backup_failed: { title: "A scheduled backup did not complete", detail: () => "The last scheduled run for this machine failed or could not start.",
    todo: "Open the machine's backup schedule and Activity to see the reason. The machine is started again after a failed run if it was running before." },
  nightly_boot_failed: { title: "The nightly boot check failed", detail: () => "A real virtual machine could not be started and reached last night.",
    todo: "Run the check by hand with svavyom-ctl nightly-boot and read its output. A host that cannot boot a guest cannot be relied on." },
};

export const unknownRule = (type: string): RuleText => ({ title: type, detail: () => "", todo: "" });
export const ruleOf = (type: string): RuleText => RULES[type] ?? unknownRule(type);

export const SEVERITY: Record<Event["severity"], { text: string; tone: "bad" | "warn" | "neutral" }> = {
  critical: { text: "Critical", tone: "bad" }, warning: { text: "Warning", tone: "warn" }, info: { text: "Information", tone: "neutral" },
};
export const STATE_TEXT: Record<Event["state"], string> = { open: "Open", acknowledged: "Acknowledged", resolved: "Resolved" };
