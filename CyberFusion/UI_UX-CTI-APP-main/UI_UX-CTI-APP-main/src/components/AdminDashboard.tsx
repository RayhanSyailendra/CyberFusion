import React, { useEffect, useState } from "react";
import { toast } from "sonner";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "./ui/card";

type AdminDashboardProps = {
  accessToken: string;
  apiBaseUrl: string;
};

type UserItem = {
  id: string;
  email: string;
  name: string | null;
  role: "admin" | "user";
  emailConfirmedAt: string | null;
  createdAt: string;
  lastSignInAt: string | null;
};

type ActivityLog = {
  id: number;
  user_id: string | null;
  user_email: string | null;
  action: string;
  module: string;
  details: any;
  ip_address: string | null;
  created_at: string;
};

export function AdminDashboard({
  accessToken,
  apiBaseUrl,
}: AdminDashboardProps) {
  const [activeTab, setActiveTab] = useState<"users" | "logs">("users");

  const [users, setUsers] = useState<UserItem[]>([]);
  const [logs, setLogs] = useState<ActivityLog[]>([]);
  const [loading, setLoading] = useState(false);

  const [newUser, setNewUser] = useState({
    email: "",
    password: "",
    name: "",
    role: "user",
  });

  const fetchUsers = async () => {
    try {
      setLoading(true);

      const res = await fetch(`${apiBaseUrl}/admin/users`, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch users");
      }

      setUsers(data.users || []);
    } catch (error: any) {
      toast.error(error.message);
    } finally {
      setLoading(false);
    }
  };

  const fetchLogs = async () => {
    try {
      setLoading(true);

      const res = await fetch(`${apiBaseUrl}/admin/activity-logs?limit=50`, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || "Failed to fetch activity logs");
      }

      setLogs(data.logs || []);
    } catch (error: any) {
      toast.error(error.message);
    } finally {
      setLoading(false);
    }
  };

  const createUser = async () => {
    try {
      if (!newUser.email || !newUser.password) {
        toast.error("Email and password are required");
        return;
      }

      const res = await fetch(`${apiBaseUrl}/admin/users`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify(newUser),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || "Failed to create user");
      }

      toast.success("User created successfully");

      setNewUser({
        email: "",
        password: "",
        name: "",
        role: "user",
      });

      fetchUsers();
    } catch (error: any) {
      toast.error(error.message);
    }
  };

  const updateUserRole = async (userId: string, role: "admin" | "user") => {
    try {
      const res = await fetch(`${apiBaseUrl}/admin/users/${userId}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({ role }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || "Failed to update user role");
      }

      toast.success("User role updated");
      fetchUsers();
    } catch (error: any) {
      toast.error(error.message);
    }
  };

  const deleteUser = async (userId: string) => {
    const confirmed = window.confirm(
      "Are you sure you want to delete this user?",
    );

    if (!confirmed) return;

    try {
      const res = await fetch(`${apiBaseUrl}/admin/users/${userId}`, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || "Failed to delete user");
      }

      toast.success("User deleted successfully");
      fetchUsers();
    } catch (error: any) {
      toast.error(error.message);
    }
  };

  useEffect(() => {
    if (activeTab === "users") {
      fetchUsers();
    } else {
      fetchLogs();
    }
  }, [activeTab]);

  return (
    <div className="min-h-screen p-6 bg-background">
      <div className="mx-auto max-w-7xl space-y-6">
        <div>
          <h1 className="text-3xl font-bold">Admin Dashboard</h1>
          <p className="text-muted-foreground">
            Manage users and monitor system activity logs.
          </p>
        </div>

        <div className="flex gap-2">
          <Button
            variant={activeTab === "users" ? "default" : "outline"}
            onClick={() => setActiveTab("users")}
          >
            Manage Users
          </Button>

          <Button
            variant={activeTab === "logs" ? "default" : "outline"}
            onClick={() => setActiveTab("logs")}
          >
            Activity Logs
          </Button>
        </div>

        {activeTab === "users" && (
          <div className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Add New User</CardTitle>
                <CardDescription>
                  Create a new user account from admin dashboard.
                </CardDescription>
              </CardHeader>

              <CardContent>
                <div className="grid grid-cols-1 gap-3 md:grid-cols-5">
                  <Input
                    placeholder="Name"
                    value={newUser.name}
                    onChange={(e) =>
                      setNewUser({ ...newUser, name: e.target.value })
                    }
                  />

                  <Input
                    placeholder="Email"
                    type="email"
                    value={newUser.email}
                    onChange={(e) =>
                      setNewUser({ ...newUser, email: e.target.value })
                    }
                  />

                  <Input
                    placeholder="Password"
                    type="password"
                    value={newUser.password}
                    onChange={(e) =>
                      setNewUser({ ...newUser, password: e.target.value })
                    }
                  />

                  <select
                    className="rounded-md border bg-background px-3 py-2 text-sm"
                    value={newUser.role}
                    onChange={(e) =>
                      setNewUser({ ...newUser, role: e.target.value })
                    }
                  >
                    <option value="user">User</option>
                    <option value="admin">Admin</option>
                  </select>

                  <Button onClick={createUser}>Add User</Button>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Manage Users</CardTitle>
                <CardDescription>
                  View, update role, and delete users.
                </CardDescription>
              </CardHeader>

              <CardContent>
                {loading ? (
                  <p>Loading users...</p>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full border-collapse text-sm">
                      <thead>
                        <tr className="border-b text-left">
                          <th className="p-3">Email</th>
                          <th className="p-3">Name</th>
                          <th className="p-3">Role</th>
                          <th className="p-3">Email Status</th>
                          <th className="p-3">Created At</th>
                          <th className="p-3">Last Sign In</th>
                          <th className="p-3">Actions</th>
                        </tr>
                      </thead>

                      <tbody>
                        {users.map((user) => (
                          <tr key={user.id} className="border-b">
                            <td className="p-3">{user.email}</td>
                            <td className="p-3">{user.name || "-"}</td>
                            <td className="p-3">
                              <select
                                className="rounded-md border bg-background px-2 py-1"
                                value={user.role}
                                onChange={(e) =>
                                  updateUserRole(
                                    user.id,
                                    e.target.value as "admin" | "user",
                                  )
                                }
                              >
                                <option value="user">User</option>
                                <option value="admin">Admin</option>
                              </select>
                            </td>
                            <td className="p-3">
                              {user.emailConfirmedAt ? (
                                <span className="rounded-full bg-green-100 px-2 py-1 text-xs text-green-700">
                                  Confirmed
                                </span>
                              ) : (
                                <span className="rounded-full bg-yellow-100 px-2 py-1 text-xs text-yellow-700">
                                  Waiting
                                </span>
                              )}
                            </td>
                            <td className="p-3">
                              {user.createdAt
                                ? new Date(user.createdAt).toLocaleString()
                                : "-"}
                            </td>
                            <td className="p-3">
                              {user.lastSignInAt
                                ? new Date(user.lastSignInAt).toLocaleString()
                                : "-"}
                            </td>
                            <td className="p-3">
                              <Button
                                variant="destructive"
                                size="sm"
                                onClick={() => deleteUser(user.id)}
                              >
                                Delete
                              </Button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        )}

        {activeTab === "logs" && (
          <Card>
            <CardHeader>
              <CardTitle>Activity Logs</CardTitle>
              <CardDescription>
                Monitor platform activity and security audit events.
              </CardDescription>
            </CardHeader>

            <CardContent>
              <div className="mb-4">
                <Button onClick={fetchLogs} variant="outline">
                  Refresh Logs
                </Button>
              </div>

              {loading ? (
                <p>Loading logs...</p>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full border-collapse text-sm">
                    <thead>
                      <tr className="border-b text-left">
                        <th className="p-3">Time</th>
                        <th className="p-3">User Email</th>
                        <th className="p-3">Action</th>
                        <th className="p-3">Module</th>
                        {/* <th className="p-3">IP Address</th> */}
                        <th className="p-3">Details</th>
                      </tr>
                    </thead>

                    <tbody>
                      {logs.map((log) => (
                        <tr key={log.id} className="border-b align-top">
                          <td className="p-3">
                            {log.created_at
                              ? new Date(log.created_at).toLocaleString()
                              : "-"}
                          </td>
                          <td className="p-3">{log.user_email || "-"}</td>
                          <td className="p-3 font-medium">{log.action}</td>
                          <td className="p-3">{log.module}</td>
                          {/* <td className="p-3">{log.ip_address || "-"}</td> */}
                          <td className="p-3">
                            <pre className="max-w-md overflow-x-auto rounded-md bg-muted p-2 text-xs">
                              {JSON.stringify(log.details, null, 2)}
                            </pre>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}
