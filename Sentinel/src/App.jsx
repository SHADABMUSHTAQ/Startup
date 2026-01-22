import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Home from "./assets/Pages/Home/Home";
import Login from "./assets/Pages/Login/Login"; 
import Navbar from "./assets/Components/Navbar/Navbar"; 
import Dashboard from "./assets/Pages/Dashboard/Dashboard";

// ✅ PATH FIXED: "assets" add kiya hai
import Payment from "./assets/Components/Payment/Payment"; 

const App = () => {
  return (
    <Router>
      <Navbar />
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/login" element={<Login />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/payment" element={<Payment />} />
      </Routes>
    </Router>
  );
};

export default App;