import streamlit as st
import sqlite3
import bcrypt
from datetime import datetime

# Database Setup
def create_tables():
    conn = sqlite3.connect('task_manager.db')
    c = conn.cursor()

    # User table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                )''')

    # Task table
    c.execute('''CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    task_name TEXT NOT NULL,
                    description TEXT,
                    priority TEXT,
                    deadline DATE,
                    status TEXT,
                    project TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )''')
    conn.commit()
    conn.close()

# User Registration
def register_user(username, password):
    conn = sqlite3.connect('task_manager.db')
    c = conn.cursor()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False

# User Authentication
def authenticate_user(username, password):
    conn = sqlite3.connect('task_manager.db')
    c = conn.cursor()
    c.execute('SELECT id, password FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    if user and bcrypt.checkpw(password.encode('utf-8'), user[1]):
        return user[0]
    return None

# Add Task
def add_task(user_id, task_name, description, priority, deadline, status, project):
    conn = sqlite3.connect('task_manager.db')
    c = conn.cursor()
    c.execute('''INSERT INTO tasks (user_id, task_name, description, priority, deadline, status, project)
                 VALUES (?, ?, ?, ?, ?, ?, ?)''',
              (user_id, task_name, description, priority, deadline, status, project))
    conn.commit()
    conn.close()

# Retrieve Tasks
def get_tasks(user_id):
    conn = sqlite3.connect('task_manager.db')
    c = conn.cursor()
    c.execute('SELECT * FROM tasks WHERE user_id = ?', (user_id,))
    tasks = c.fetchall()
    conn.close()
    return tasks

# Admin: Retrieve All Users and Tasks
def get_all_users_and_tasks():
    conn = sqlite3.connect('task_manager.db')
    c = conn.cursor()
    c.execute('''SELECT users.username, tasks.task_name, tasks.description, tasks.priority, tasks.deadline,
                 tasks.status, tasks.project FROM tasks JOIN users ON tasks.user_id = users.id''')
    data = c.fetchall()
    conn.close()
    return data

# Streamlit App
create_tables()
st.title("Task Manager")

# Session State for User
if 'user_id' not in st.session_state:
    st.session_state.user_id = None

# Login/Register
if st.session_state.user_id is None:
    option = st.selectbox("Select Option", ["Login", "Register"])

    if option == "Register":
        st.subheader("Register")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Register"):
            if register_user(username, password):
                st.success("Registration successful. You can now log in.")
            else:
                st.error("Username already exists. Try a different one.")

    elif option == "Login":
        st.subheader("Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            user_id = authenticate_user(username, password)
            if user_id:
                st.session_state.user_id = user_id
                st.success("Login successful.")
            else:
                st.error("Invalid username or password.")

else:
    # Main Interface
    st.sidebar.header("Menu")
    menu = st.sidebar.selectbox("Options", ["Tasks", "Admin", "Logout"])

    if menu == "Tasks":
        st.subheader("Your Tasks")

        # Add Task
        with st.form("add_task_form"):
            st.write("Add New Task")
            task_name = st.text_input("Task Name")
            description = st.text_area("Description")
            priority = st.selectbox("Priority", ["Low", "Medium", "High"])
            deadline = st.date_input("Deadline")
            status = st.selectbox("Status", ["Pending", "In Progress", "Completed"])
            project = st.text_input("Project")
            submitted = st.form_submit_button("Add Task")
            if submitted:
                add_task(st.session_state.user_id, task_name, description, priority, deadline, status, project)
                st.success("Task added successfully.")

        # Display Tasks
        tasks = get_tasks(st.session_state.user_id)
        if tasks:
            for task in tasks:
                st.write(f"**{task[2]}** ({task[5]}) - {task[6]}")
                st.write(f"Priority: {task[3]} | Due: {task[4]}")
                st.write(f"Description: {task[3]}")
                st.markdown("---")
        else:
            st.write("No tasks found.")

    elif menu == "Admin":
        st.subheader("Admin Panel")
        admin_data = get_all_users_and_tasks()
        if admin_data:
            for row in admin_data:
                st.write(f"**User:** {row[0]} | **Task:** {row[1]} | **Priority:** {row[3]} | **Deadline:** {row[4]} | **Status:** {row[5]} | **Project:** {row[6]}")
                st.markdown("---")
        else:
            st.write("No data found.")

    elif menu == "Logout":
        st.session_state.user_id = None
        st.experimental_rerun()