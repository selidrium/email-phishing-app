import React, { useEffect, useState } from "react";
import axios from "axios";
import { extractErrorMessage } from './utils/errorHandler';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL || "http://localhost:8000";

export default function AdminPanel({ token }) {
  const [users, setUsers] = useState([]);
  const [adminStats, setAdminStats] = useState(null);
  const [editingUser, setEditingUser] = useState(null);
  const [editForm, setEditForm] = useState({ username: "", email: "", is_admin: false });
  const [message, setMessage] = useState("");

  useEffect(() => {
    if (token) {
      loadUsers();
      loadAdminStats();
    }
    // eslint-disable-next-line
  }, [token]);

  const showMessage = (msg) => {
    // Ensure message is always a string
    const messageString = typeof msg === 'string' ? msg : JSON.stringify(msg);
    setMessage(messageString);
    setTimeout(() => setMessage(""), 4000);
  };

  const loadUsers = async () => {
    try {
      const res = await axios.get(`${API_BASE_URL}/admin/users`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setUsers(res.data.users);
    } catch (err) {
      const errorMessage = extractErrorMessage(err, "Failed to load users.");
      showMessage(errorMessage);
    }
  };

  const loadAdminStats = async () => {
    try {
      const res = await axios.get(`${API_BASE_URL}/admin/stats`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setAdminStats(res.data);
    } catch (err) {
      const errorMessage = extractErrorMessage(err, "Failed to load admin stats.");
      showMessage(errorMessage);
    }
  };

  const deleteUser = async (userId, username) => {
    if (!window.confirm(`Delete user "${username}"?`)) return;
    try {
      await axios.delete(`${API_BASE_URL}/admin/users/${userId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      showMessage(`User "${username}" deleted.`);
      loadUsers();
      loadAdminStats();
    } catch (err) {
      const errorMessage = extractErrorMessage(err, "Failed to delete user.");
      showMessage(errorMessage);
    }
  };

  const updateUser = async (userId) => {
    try {
      await axios.put(`${API_BASE_URL}/admin/users/${userId}`, editForm, {
        headers: { Authorization: `Bearer ${token}` },
      });
      showMessage("User updated.");
      setEditingUser(null);
      setEditForm({ username: "", email: "", is_admin: false });
      loadUsers();
    } catch (err) {
      const errorMessage = extractErrorMessage(err, "Failed to update user.");
      showMessage(errorMessage);
    }
  };

  const startEditUser = (user) => {
    setEditingUser(user.id);
    setEditForm({ 
      username: user.username, 
      email: user.email, 
      is_admin: user.is_admin 
    });
  };

  const cancelEdit = () => {
    setEditingUser(null);
    setEditForm({ username: "", email: "", is_admin: false });
  };

  return (
    <div>
      <h2 className="mb-4">Admin Panel</h2>
      {message && <div className="alert alert-info">{message}</div>}
      {adminStats && (
        <div className="row mb-4">
          <div className="col-md-3">
            <div className="card bg-primary text-white">
              <div className="card-body text-center">
                <h3>{adminStats.total_users}</h3>
                <p className="mb-0">Total Users</p>
              </div>
            </div>
          </div>
          <div className="col-md-3">
            <div className="card bg-success text-white">
              <div className="card-body text-center">
                <h3>{adminStats.total_emails}</h3>
                <p className="mb-0">Total Emails</p>
              </div>
            </div>
          </div>
          <div className="col-md-3">
            <div className="card bg-danger text-white">
              <div className="card-body text-center">
                <h3>{adminStats.phishing_emails}</h3>
                <p className="mb-0">Phishing Emails</p>
              </div>
            </div>
          </div>
          <div className="col-md-3">
            <div className="card bg-info text-white">
              <div className="card-body text-center">
                <h3>{adminStats.phishing_rate?.toFixed(1)}%</h3>
                <p className="mb-0">Phishing Rate</p>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="card shadow-lg">
        <div className="card-header bg-dark text-white">
          <h4 className="mb-0">
            <i className="bi bi-people me-2"></i>
            User Management
          </h4>
        </div>
        <div className="card-body">
          <div className="table-responsive">
            <table className="table table-striped">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Username</th>
                  <th>Email</th>
                  <th>Admin</th>
                  <th>Emails Count</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((user) => (
                  <tr key={user.id}>
                    <td>{user.id}</td>
                    <td>
                      {editingUser === user.id ? (
                        <input
                          type="text"
                          className="form-control form-control-sm"
                          value={editForm.username}
                          onChange={(e) =>
                            setEditForm({ ...editForm, username: e.target.value })
                          }
                        />
                      ) : (
                        user.username
                      )}
                    </td>
                    <td>
                      {editingUser === user.id ? (
                        <input
                          type="email"
                          className="form-control form-control-sm"
                          value={editForm.email}
                          onChange={(e) =>
                            setEditForm({ ...editForm, email: e.target.value })
                          }
                        />
                      ) : (
                        user.email
                      )}
                    </td>
                    <td>
                      {editingUser === user.id ? (
                        <div className="form-check">
                          <input
                            className="form-check-input"
                            type="checkbox"
                            checked={editForm.is_admin}
                            onChange={(e) =>
                              setEditForm({ ...editForm, is_admin: e.target.checked })
                            }
                          />
                        </div>
                      ) : (
                        <span className={`badge ${user.is_admin ? 'bg-warning' : 'bg-secondary'}`}>
                          {user.is_admin ? 'Admin' : 'User'}
                        </span>
                      )}
                    </td>
                    <td>{user.email_count}</td>
                    <td>
                      {user.created_at ? new Date(user.created_at).toLocaleDateString() : 'N/A'}
                    </td>
                    <td>
                      {editingUser === user.id ? (
                        <div className="btn-group btn-group-sm">
                          <button
                            className="btn btn-success"
                            onClick={() => updateUser(user.id)}
                          >
                            <i className="bi bi-check"></i>
                          </button>
                          <button
                            className="btn btn-secondary"
                            onClick={cancelEdit}
                          >
                            <i className="bi bi-x"></i>
                          </button>
                        </div>
                      ) : (
                        <div className="btn-group btn-group-sm">
                          <button
                            className="btn btn-primary"
                            onClick={() => startEditUser(user)}
                          >
                            <i className="bi bi-pencil"></i>
                          </button>
                          <button
                            className="btn btn-danger"
                            onClick={() => deleteUser(user.id, user.username)}
                            disabled={user.is_admin}
                          >
                            <i className="bi bi-trash"></i>
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
} 