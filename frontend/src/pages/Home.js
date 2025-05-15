// src/pages/Home.jsx
import React, { useContext } from "react";
import { AuthContext } from "../contexts/AuthContext";
import { CartContext } from "../contexts/CartContext";
import { Link } from "react-router-dom";

const records = [
  { id: 1, title: "Jazz Vibes", artist: "Cool Quartet", price: 25 },
  { id: 2, title: "Classical Calm", artist: "Symphony Orchestra", price: 30 },
  { id: 3, title: "Rock Legends", artist: "The Rockers", price: 20 },
];

export default function Home() {
  const { user } = useContext(AuthContext);
  const { addToCart } = useContext(CartContext);

  return (
    <div className="container">
      <header>
        {user ? (
          <>
            <p>Привет, {user.name}!</p>
            <Link to="/cart">Корзина</Link>
            <Link to="/profile">Профиль</Link>
          </>
        ) : (
          <>
            <Link to="/login">Войти</Link>
            <Link to="/register">Регистрация</Link>
          </>
        )}
      </header>

      <h1>Каталог пластинок</h1>
      <div className="records-grid">
        {records.map((rec) => (
          <div key={rec.id} className="record-card">
            <div>
              <h3 className="record-title">{rec.title}</h3>
              <p className="record-artist">{rec.artist}</p>
              <p className="record-price">${rec.price}</p>
            </div>
            {user ? (
              <button onClick={() => addToCart(rec)}>Добавить в корзину</button>
            ) : (
              <button disabled title="Войдите, чтобы купить">
                Войдите, чтобы купить
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
