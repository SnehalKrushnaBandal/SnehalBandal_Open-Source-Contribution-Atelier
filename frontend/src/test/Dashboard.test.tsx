import { cleanup, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { DashboardPage } from "../pages/DashboardPage";

const mockUseAuth = vi.fn();

vi.mock("../features/auth/AuthContext", () => ({
  useAuth: () => mockUseAuth(),
}));

vi.mock("../components/dashboard/AdminDashboard", () => ({
  AdminDashboard: () => <div>Admin dashboard</div>,
}));

vi.mock("../components/dashboard/ContributorDashboard", () => ({
  ContributorDashboard: () => <div>Contributor dashboard</div>,
}));

describe("DashboardPage", () => {
  beforeEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("renders the admin dashboard for staff users", () => {
    mockUseAuth.mockReturnValue({
      user: { id: 1, username: "maintainer_jane", is_staff: true },
    });

    render(<DashboardPage />);

    expect(screen.getByText("Admin dashboard")).toBeInTheDocument();
    expect(screen.queryByText("Contributor dashboard")).not.toBeInTheDocument();
  });

  it("renders the contributor dashboard for regular users", () => {
    mockUseAuth.mockReturnValue({
      user: { id: 2, username: "bob_coder", is_staff: false },
    });

    render(<DashboardPage />);

    expect(screen.getByText("Contributor dashboard")).toBeInTheDocument();
    expect(screen.queryByText("Admin dashboard")).not.toBeInTheDocument();
  });
});
