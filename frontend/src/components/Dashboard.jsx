import { useState, useEffect } from 'react';
import axios from 'axios';

const API_BASE_URL = 'https://expense-7c53.onrender.com';

function Dashboard({ user, onLogout }) {
  const [expenses, setExpenses] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);

  const [expenseData, setExpenseData] = useState({
    title: '',
    amount: '',
    category: 'Food',
  });

  const [message, setMessage] = useState({ type: '', text: '' });

  // ================= FETCH DATA =================
  useEffect(() => {
    fetchAll();
  }, []);

  const fetchAll = async () => {
    try {
      setLoading(true);

      const [expRes, totalRes] = await Promise.all([
        axios.get(`${API_BASE_URL}/expenses`),
        axios.get(`${API_BASE_URL}/expenses/total`)
      ]);

      setExpenses(expRes.data || []);
      setTotal(totalRes.data.total || 0);

    } catch (err) {
      console.error(err);
      setMessage({ type: 'error', text: 'Failed to load data' });
    } finally {
      setLoading(false);
    }
  };

  // ================= HANDLE INPUT =================
  const handleChange = (e) => {
    setExpenseData({ ...expenseData, [e.target.name]: e.target.value });
  };

  // ================= ADD EXPENSE =================
  const handleAddExpense = async (e) => {
    e.preventDefault();
    setMessage({ type: '', text: '' });

    if (!expenseData.title || !expenseData.amount) {
      return setMessage({ type: 'error', text: 'All fields are required' });
    }

    try {
      await axios.post(`${API_BASE_URL}/expense`, {
        ...expenseData,
        amount: Number(expenseData.amount),
      });

      setMessage({ type: 'success', text: '✅ Expense added successfully' });

      setExpenseData({ title: '', amount: '', category: 'Food' });

      fetchAll();

    } catch (err) {
      setMessage({
        type: 'error',
        text: err.response?.data?.message || 'Failed to add expense',
      });
    }
  };

  // ================= UI =================
  return (
    <div className="dashboard">

      {/* HEADER */}
      <div className="header">
        <h2>👋 Hello, {user?.name || "User"}</h2>
        <button onClick={onLogout} className="logout">Logout</button>
      </div>

      {/* TOTAL */}
      <div className="total-box">
        ₹ {total}
        <div style={{ fontSize: '14px', fontWeight: 'normal' }}>
          Total Spent
        </div>
      </div>

      {/* MESSAGE */}
      {message.text && (
        <p className={message.type === 'error' ? 'error' : 'success'}>
          {message.text}
        </p>
      )}

      {/* FORM */}
      <form onSubmit={handleAddExpense} className="expense-form">
        <input
          name="title"
          placeholder="Expense Title"
          value={expenseData.title}
          onChange={handleChange}
        />

        <input
          name="amount"
          type="number"
          placeholder="Amount"
          value={expenseData.amount}
          onChange={handleChange}
        />

        <select
          name="category"
          value={expenseData.category}
          onChange={handleChange}
        >
          <option>Food</option>
          <option>Travel</option>
          <option>Bills</option>
          <option>Shopping</option>
          <option>Entertainment</option>
          <option>Health</option>
          <option>Others</option>
        </select>

        <button type="submit">Add Expense</button>
      </form>

      {/* LIST */}
      <div className="list">

        {loading ? (
          <p style={{ textAlign: 'center' }}>Loading...</p>
        ) : expenses.length === 0 ? (
          <p style={{ textAlign: 'center' }}>No expenses yet 🚫</p>
        ) : (
          expenses.map((exp, i) => (
            <div key={i} className="item">
              <div>
                <strong>{exp.title}</strong>
                <div style={{ fontSize: '12px', opacity: 0.7 }}>
                  {new Date(exp.date).toLocaleDateString('en-IN')}
                </div>
              </div>

              <div style={{ textAlign: 'right' }}>
                <div style={{ fontWeight: 'bold' }}>₹{exp.amount}</div>
                <span>{exp.category}</span>
              </div>
            </div>
          ))
        )}

      </div>
    </div>
  );
}

export default Dashboard;