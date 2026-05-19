"use client"

import { useEffect, useState } from "react"
import { supabase } from "@/lib/supabase"

// VULNERABILITY: DOM XSS via innerHTML from URL hash
// Scanner: dom_xss_scanner (#22)
// VULNERABILITY: Token stored in localStorage
// Scanner: session_scanner (#5)

export default function Dashboard() {
  const [tasks, setTasks] = useState([])

  useEffect(() => {
    // VULNERABILITY: Stores auth token in localStorage (XSS = token theft)
    const token = localStorage.getItem("access_token")
    if (!token) {
      window.location.href = "/login"
      return
    }

    // VULNERABILITY: DOM XSS — renders URL hash as HTML without sanitization
    const preview = document.getElementById("task-preview")
    if (preview && window.location.hash) {
      preview.innerHTML = decodeURIComponent(window.location.hash.slice(1))
    }

    // Fetch tasks
    fetch("/api/tasks", {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((r) => r.json())
      .then(setTasks)
  }, [])

  // Fetch from Supabase directly (exposes anon key in network tab)
  useEffect(() => {
    supabase.from("tasks").select("*").then(({ data }) => {
      if (data) setTasks(data)
    })
  }, [])

  return (
    <div>
      <h1>My Tasks</h1>
      <div id="task-preview"></div>
      <ul>
        {tasks.map((task: any) => (
          <li key={task.id}>{task.title}</li>
        ))}
      </ul>
    </div>
  )
}
