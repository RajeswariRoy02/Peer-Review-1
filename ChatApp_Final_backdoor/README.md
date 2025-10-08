# Chat System Project-Group 22

## Group Members
-Yiduo Chu a1910298
-Ho Long Lau a1961403
-Yunsong Wang a1905686
-Xueqing Liang a1978501
-Sok Teng Ao a1930429

## Requirements

- Node.js (version >= 18.0.0)
- npm
- Modern web browser

## Installation

```bash
# Install frontend dependencies
cd frontend && npm install

# Install backend dependencies
cd ../backend && npm install
```

## Running the Project

### 1. Install Dependencies (First Time Setup)

In your local terminal:
```bash
cd backend
npm install
```

### 2. Start Backend Server

In your local terminal:
```bash
cd backend
node src/index.js
```

### 3. Start Frontend (Simulate Two Users)

Open two new terminal windows(like two users) and run:
```bash
npm run dev
```

### 4. Using the Application

1. Open the displayed URL in your browser
2. Generate keys and connect directly on the webpage
3. Two user interfaces can send messages to each other

### 5. Key Management and Login Options

**Automatic Key Download:**
- After generating keys and logging in, the system automatically downloads a `.json` file containing your public+ private keys

**Two Login Methods:**
1. **Upload JSON File:** Use the "Upload Keys" button to  upload your downloaded `.json` file
2. **Paste Keys:** Use the "Paste Keys" button to manually copy and paste the public key and private key from your `.json` file

## Others
1. You can change the host and port settings in backend/src/index.js and frontend/src/App.jsx when testing locally.
2. The detailed protocol can be found in backend/src/index.js.
