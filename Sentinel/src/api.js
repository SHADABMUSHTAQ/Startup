const API_URL = "http://127.0.0.1:8000/api/v1/auth";

export async function registerUser(name, email, password) {
  const response = await fetch(`${API_URL}/signup`, {  // <-- yahan /register ko /signup se replace karo
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ 
      full_name: name,      // backend ke SignupModel ke fields ke according
      username: name,       // username bhi chahiye
      email,
      password
    }),
  });

  if (!response.ok) {
    const data = await response.json();
    throw new Error(data.detail || "Signup failed");
  }

  return await response.json();
}
