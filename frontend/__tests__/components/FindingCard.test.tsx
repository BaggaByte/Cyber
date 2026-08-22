import { render, screen } from "@testing-library/react";
import "@testing-library/jest-dom";

// Simple smoke test for now
describe("Scan Results Component", () => {
  it("renders mock text", () => {
    render(<div>Mock Page</div>);
    expect(screen.getByText("Mock Page")).toBeInTheDocument();
  });
});

