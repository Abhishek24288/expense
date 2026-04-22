import { useState } from 'react';
import axios from 'axios';

const API_BASE_URL = 'https://expense-7c53.onrender.com';

function Register({ onSuccess }) {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: '',
  });

  const [message, setMessage] = useState({ type: '', text: '' });
  const [loading, setLoading] = useState(false);

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage({ type: '', text: '' });

    if (formData.password.length < 6) {
      return setMessage({ type: 'error', text: 'Password must be at least 6 characters' });
    }

    try {
      setLoading(true);
      const res = await axios.post(`${API_BASE_URL}/register`, formData);

      setMessage({ type: 'success', text: res.data.message || 'Registered successfully!' });

      setFormData({ name: '', email: '', password: '' });

      onSuccess && onSuccess();

    } catch (err) {
      setMessage({
        type: 'error',
        text: err.response?.data?.message || 'Registration failed',
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card">
      <h2>Create Account</h2>

      {message.text && (
        <p className={message.type === 'error' ? 'error' : 'success'}>
          {message.text}
        </p>
      )}

      <form onSubmit={handleSubmit}>
        <input name="name" placeholder="Full Name" value={formData.name} onChange={handleChange} required />
        <input name="email" type="email" placeholder="Email" value={formData.email} onChange={handleChange} required />
        <input name="password" type="password" placeholder="Password" value={formData.password} onChange={handleChange} required />

        <button disabled={loading}>
          {loading ? 'Creating Account...' : 'Register'}
        </button>
      </form>
    </div>
  );
}

export default Register;