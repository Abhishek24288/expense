import { useState } from 'react';
import Register from './components/Register';
import Login from './components/Login';
import Dashboard from './components/Dashboard';
import './App.css';

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [user, setUser] = useState(null);

  const handleLoginSuccess = (token, userData) => {
    setUser(userData);
    setIsLoggedIn(true);
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    setIsLoggedIn(false);
    setUser(null);
  };

  return (
    <div className="app">
      <h1>💰 Personal Expense Manager</h1>

      {!isLoggedIn ? (
        <div className="container">
          <Register />
          <Login onLoginSuccess={handleLoginSuccess} />
        </div>
      ) : (
        <Dashboard user={user} onLogout={handleLogout} />
      )}
    </div>
  );
}

export default App;