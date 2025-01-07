# 🎮 CyberZone - Gaming Club Management System

## 📌 Overview
**CyberZone** is an advanced gaming club management system tailored to streamline operations for gaming clubs and improve customer experiences. Designed with both administrators and players in mind, the platform enables easy reservations, membership tracking, and seamless event management. Its primary focus is to make gaming club operations efficient, organized, and enjoyable.

---

## 🎯 Purpose and Target Audience

### **Purpose**
CyberZone aims to:
- Automate and simplify gaming club management.
- Provide players with a better booking and event experience.
- Enable administrators to focus more on customer satisfaction rather than manual tasks.

### **Target Audience**
1. **Gaming Club Owners**:
   - Efficiently manage reservations and memberships.
   - Organize tournaments and track popular games.
2. **Gamers**:
   - Seamlessly book gaming stations or participate in tournaments.
   - Access leaderboards and track their gaming achievements.

---

## 🛠 Features
1. **Authentication & Authorization**:
   - Secure login system for admins and players.
   - Role-based access control (Admin/Player).
2. **Real-time Game Booking**:
   - Reserve gaming stations or rooms.
   - Check availability in real-time.
3. **Membership Management**:
   - Different membership tiers with perks.
   - Automated reminders for membership renewals.
4. **Game Leaderboards**:
   - Track top players and most popular games.
5. **Admin Panel** (Upcoming):
   - Manage users, bookings, and tournaments.
   - View club performance and analytics.
6. **User Pages**:
   - Book gaming stations.
   - Participate in tournaments and view leaderboards.
7. **Reports and Analytics**:
   - Insights into club performance.
   - Statistics on usage, membership growth, and popular games.

---

## 🌟 Screenshots

### **Home Page**


![Image alt](https://github.com/dilyar111/cyberzone/blob/main/Снимок%20экрана%202024-12-19%20в%2017.16.09.png)

### **Booking Page**

![Image alt2](https://github.com/dilyar111/cyberzone/blob/main/Снимок%20экрана%202024-12-19%20в%2017.16.25.png)

### **(Upcoming) Admin Panel Mockup**
A dedicated admin page will be introduced soon. This page will allow administrators to manage users, bookings, and events, as well as access analytics and performance metrics to streamline club operations.


---

## 📝 How to Start the Project

### Step 1: Clone the Repository
1. Open a terminal on your computer.
2. Run the following command to clone the repository to your local machine:
   ```bash
   git clone https://github.com/yourusername/cyberzone.git
   ```
3. Navigate to the project directory:
   ```bash
   cd cyberzone
   ```

### Step 2: Start the Backend Server
1. Go to the backend folder:
   ```bash
   cd backend
   ```
2. Ensure you have Go installed on your machine. Check by running:
   ```bash
   go version
   ```
   If Go is not installed, download it from [Go Downloads](https://go.dev/dl/).
3. Install backend dependencies:
   ```bash
   go mod tidy
   ```
4. Configure your database connection in the `config.go` file. Example configuration:
   ```go
   const (
       DBHost     = "localhost"
       DBPort     = 5432
       DBUser     = "your_postgres_user"
       DBPassword = "your_password"
       DBName     = "cyberzone"
   )
   ```
5. Run the backend server:
   ```bash
   go run main.go
   ```
   The server will start running at [http://localhost:8080](http://localhost:8080).

### Step 3: Prepare the Database
1. Ensure PostgreSQL is installed and running on your machine.
2. Log in to PostgreSQL:
   ```bash
   psql -U your_postgres_user
   ```
3. Create a new database:
   ```sql
   CREATE DATABASE cyberzone;
   ```
4. Import the database schema:
   ```bash
   psql -U your_postgres_user -d cyberzone -f database/schema.sql
   ```

### Step 4: Open the Frontend Web Page
1. Navigate to the frontend folder:
   ```bash
   cd ../frontend
   ```
2. Open the `index.html` file in your preferred browser for the user interface.
   - On most systems, you can open the file by simply double-clicking it.
   - Alternatively, use a local server for a better experience (e.g., Live Server extension in VS Code).
3. (Upcoming) To test the admin page, open `admin.html` (once available).

### Step 5: Testing the Application
1. **User Dashboard**:
   - Open `index.html` in your browser and interact with the features such as booking systems and leaderboards.
2. **API Endpoints**:
   - Use Postman or a similar tool to test backend API endpoints.
   - Example requests:
     ```
     POST http://localhost:8080/api/login
     POST http://localhost:8080/api/bookings
     ```

### Step 6: Optional - Run the Project with Docker
1. Ensure Docker is installed and running on your system.
2. Use the following command to build and run the project:
   ```bash
   docker-compose up --build
   ```
3. Access the application in your browser:
   - Frontend: [http://localhost:3000](http://localhost:3000)
   - Backend API: [http://localhost:8080](http://localhost:8080)

---

## API Documentation

## Endpoints

### POST `/api/login`
Logs in a user and returns a token.

### POST `/api/bookings`
Creates a new booking.

### GET `/api/leaderboard`
Fetches the leaderboard data.

### POST `/api/events`
Admins can create a new event.

---

## 🛠️ Technologies Used

- **Programming Language:** Go (Golang) for backend development.
- **Frontend:** HTML, CSS, JavaScript.
- **Database:** PostgreSQL.
- **Testing Tools:** Postman for API testing.
- **Containerization:** Docker for deployment.
- **Version Control:** Git & GitHub.

---

## 🧪 Testing

To test the application:
1. Use **Postman** for API requests.
2. Test the frontend on `http://localhost:3000`.
3. Ensure the backend is running at `http://localhost:8080`.

---

