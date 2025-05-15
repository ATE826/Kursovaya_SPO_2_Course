// src/pages/Cart.jsx
import React, { useContext } from "react";
import { CartContext } from "../contexts/CartContext";
import { Link } from "react-router-dom";

export default function Cart() {
  const { cartItems, removeFromCart, clearCart } = useContext(CartContext);

  const totalPrice = cartItems.reduce((sum, item) => sum + item.price, 0);

  return (
    <div className="container">
      <h2>Корзина</h2>
      {cartItems.length === 0 ? (
        <p>Ваша корзина пуста. <Link to="/">Перейти в каталог</Link></p>
      ) : (
        <>
          <ul>
            {cartItems.map((item) => (
              <li key={item.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span>{item.title} — ${item.price}</span>
                <button onClick={() => removeFromCart(item.id)} style={{ padding: "6px 10px", fontSize: 12 }}>
                  Удалить
                </button>
              </li>
            ))}
          </ul>
          <p style={{ fontWeight: "600", fontSize: "16px", marginTop: 15 }}>
            Итого: ${totalPrice}
          </p>
          <button onClick={clearCart} style={{ marginTop: 10 }}>
            Очистить корзину
          </button>
        </>
      )}
    </div>
  );
}
