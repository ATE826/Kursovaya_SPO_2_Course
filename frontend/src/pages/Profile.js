// src/pages/Profile.jsx
import React, { useContext } from "react";
import { AuthContext } from "../contexts/AuthContext";

export default function Profile() {
  const { user, logout } = useContext(AuthContext);

  if (!user) {
    return (
      <div className="container">
        <h2>Профиль</h2>
        <p>Вы не авторизованы.</p>
      </div>
    );
  }

  return (
    <div className="container">
      <h2>Профиль пользователя</h2>
      <div className="profile-info">
        <p><strong>Имя:</strong> {user.name}</p>
        <p><strong>Email:</strong> {user.email}</p>
      </div>
      <button onClick={logout} style={{ marginTop: 20 }}>
        Выйти
      </button>
    </div>
  );
}
