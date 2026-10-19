// fe-unit: every errors.json category and every operation_status value has a UI mapping (AC01).
import { describe, expect, it } from "vitest";
import errorsContract from "../../../contracts/interfaces/errors.json";
import inventory from "../../../contracts/interfaces/inventory.json";
import resources from "../../../contracts/interfaces/resources.json";
import { BOUNDARY_CATEGORIES, ERROR_PRESENTATION, KNOWN_CATEGORIES, OPERATION_STATUS_LABEL, isRetryable, operationFlags, type OperationStatus } from "./errors";

describe("typed state mappings", () => {
  it("every errors.json category has a presentation", () => {
    expect(Object.keys(ERROR_PRESENTATION).sort()).toEqual(Object.keys(errorsContract.categories).sort());
    for (const c of KNOWN_CATEGORIES) {
      expect(ERROR_PRESENTATION[c].title.length).toBeGreaterThan(3);
      expect(ERROR_PRESENTATION[c].recovery.length).toBeGreaterThan(10);
      expect(isRetryable(c)).toBe(errorsContract.categories[c].retryable);
    }
  });

  it("boundary categories come from the browser-api inventory", () => {
    expect(BOUNDARY_CATEGORIES).toEqual(inventory.boundaries["browser-api"].error_categories);
    expect(BOUNDARY_CATEGORIES).not.toContain("timeout");
    expect(BOUNDARY_CATEGORIES).not.toContain("host_error");
  });

  it("every operation status has a label and the contract flags", () => {
    expect(Object.keys(OPERATION_STATUS_LABEL).sort()).toEqual(Object.keys(resources.operation_status).sort());
    for (const s of Object.keys(resources.operation_status) as OperationStatus[]) {
      expect(operationFlags(s)).toEqual(resources.operation_status[s]);
    }
  });
});
