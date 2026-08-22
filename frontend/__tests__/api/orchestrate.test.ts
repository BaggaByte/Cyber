/**
 * @jest-environment node
 */
import { POST } from "../../app/api/orchestrate/route";
import { NextRequest } from "next/server";

describe("POST /api/orchestrate", () => {
  beforeEach(() => {
    global.fetch = jest.fn();
  });

  it("should default target to example.com if missing", async () => {
    const req = new NextRequest("http://localhost:3000/api/orchestrate", {
      method: "POST",
      body: JSON.stringify({ target: "", goal: "Find open ports" }),
    });

    const response = await POST(req);
    expect(response.status).toBe(200);
    const data = await response.json();
    expect(data.planner_reasoning).toContain("example.com");
  });

  it("should return 400 for missing goal", async () => {
    const req = new NextRequest("http://localhost:3000/api/orchestrate", {
      method: "POST",
      body: JSON.stringify({ target: "test.com", goal: "" }),
    });

    const response = await POST(req);
    expect(response.status).toBe(400);
    const data = await response.json();
    expect(data.detail).toContain("Please provide a mission goal");
  });
});

