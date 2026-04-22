import { useState } from 'react';
import axios from 'axios';

const API_BASE_URL = 'https://expense-7c53.onrender.com';

function Login({ onLoginSuccess }) {
  const [formData, setFormData] = useState({ email: '', password: '' });
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(false);

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage('');

    try {
      setLoading(true);

      const res = await axios.post(`${API_BASE_URL}/login`, formData);

      const { token, user } = res.data;

      localStorage.setItem('token', token);
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;

      onLoginSuccess(token, user);

    } catch (err) {
      setMessage(err.response?.data?.message || 'Invalid credentials');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card">
      <h2>Welcome Back</h2>

      {message && <p className="error">{message}</p>}

      <form onSubmit={handleSubmit}>
        <input name="email" type="email" placeholder="Email" value={formData.email} onChange={handleChange} required />
        <input name="password" type="password" placeholder="Password" value={formData.password} onChange={handleChange} required />

        <button disabled={loading}>
          {loading ? 'Logging in...' : 'Login'}
        </button>
      </form>
    </div>
  );
}

export default Login;