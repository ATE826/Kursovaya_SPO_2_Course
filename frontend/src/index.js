import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './App.css'  // <-- тут импорт стилей

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
)
