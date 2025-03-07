# Expense Sharing App

A web-based expense sharing application built with Flask that helps groups track and split expenses. Perfect for roommates, trips, or any group that needs to share expenses.

## Features

- **User Management**
  - User registration and authentication
  - Secure password handling
  - Personal dashboard

- **Group Management**
  - Create and manage expense groups
  - Add/remove group members
  - View group history and balances

- **Expense Tracking**
  - Add expenses with descriptions and amounts
  - Equal splitting among group members
  - Track who paid and who owes
  - View expense history

- **Balance Management**
  - Real-time balance calculations
  - Suggested settlements to minimize transactions
  - Direct settlement recording between members

## Tech Stack

- **Backend**: Python Flask
- **Database**: SQLAlchemy (SQLite in development, PostgreSQL in production)
- **Frontend**: Bootstrap 5, JavaScript
- **Security**: Werkzeug security for password hashing

## Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd expense-sharing-app
   ```

2. **Set up a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set environment variables**
   ```bash
   export SECRET_KEY='your-secret-key'  # On Windows: set SECRET_KEY=your-secret-key
   ```

5. **Initialize the database**
   ```bash
   flask run
   ```
   The database will be automatically created on first run.

## Usage

1. **Register/Login**
   - Create a new account or login with existing credentials
   - Each user needs a unique username and email

2. **Create a Group**
   - Click "Create Group" from the dashboard
   - Give your group a name
   - You'll automatically be added as the group creator

3. **Manage Group Members**
   - Add members by their username
   - Group creator can remove members
   - Members can leave the group (except the creator)

4. **Add Expenses**
   - Enter expense description and amount
   - Select who paid
   - The expense is automatically split equally among all members

5. **Track Balances**
   - View current balances for all members
   - See suggested settlements
   - Record payments between members

6. **View History**
   - See all expenses and settlements
   - Track who participated in each expense
   - Monitor payment history

## Security Features

- Password hashing using Werkzeug
- Session-based authentication
- CSRF protection
- Input validation and sanitization
- Secure database queries using SQLAlchemy

## Deployment

The application is designed to work with both SQLite (development) and PostgreSQL (production):

- **Development**: Uses SQLite by default
- **Production**: Set `DATABASE_URL` environment variable for PostgreSQL
  ```bash
  export DATABASE_URL='postgresql://user:password@localhost/dbname'
  ```

## License

This project is licensed under the MIT License - see the LICENSE file for details. 