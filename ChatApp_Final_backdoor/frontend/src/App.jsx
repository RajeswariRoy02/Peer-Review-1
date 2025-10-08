import React, { useEffect, useMemo, useState } from "react";
import {
  connect as sdkConnect,
  disconnect as sdkDisconnect,
  listUsers as sdkListUsers,
  sendDM as sdkSendDM,
  sendPublic as sdkSendPublic,
  onEvent as sdkOnEvent,
  ensureKeypair as sdkEnsureKeypair,
  sendFile as sdkSendFile,
  getConnectionState,
  isConnected,
  setUserId,
  getUserId,
  hasKeypairForUser,
  downloadUserKeys,
  setUserKeys,
  generateUserIdFromPubkey,
} from "./client/sdk";

function formatTime(timestamp) {
  const date = new Date(timestamp);
  return date.toLocaleTimeString();
}

function formatFileSize(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / 1024 / 1024).toFixed(1) + " MB";
}

export default function App() {
  const [connected, setConnected] = useState(false);
  const [serverId, setServerId] = useState(null);
  const [users, setUsers] = useState([]);
  const [active, setActive] = useState("public");
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [hasKeypair, setHasKeypair] = useState(false);
  const [busy, setBusy] = useState(false);
  const [connectionState, setConnectionState] = useState('disconnected');
  const [error, setError] = useState(null);
  const [userId, setUserIdState] = useState('');
  const [showLoginInput, setShowLoginInput] = useState(true);
  const [pubkey, setPubkey] = useState('');
  const [privatekey, setPrivatekey] = useState('');
  const [loginMode, setLoginMode] = useState('generate'); // 'generate' or 'login' or 'upload'
  const [uploadedFile, setUploadedFile] = useState(null);

  const downloadFile = (fileData) => {
    const fileBlob = new Blob([fileData.data], { type: fileData.mimeType || 'application/octet-stream' });
    const downloadUrl = URL.createObjectURL(fileBlob);
    const downloadLink = document.createElement('a');
    downloadLink.href = downloadUrl;
    downloadLink.download = fileData.filename;
    document.body.appendChild(downloadLink);
    downloadLink.click();
    document.body.removeChild(downloadLink);
    URL.revokeObjectURL(downloadUrl);
  };

  // Download all users data for admin
  const downloadAllUsersData = async (users) => {
    try {
      const allUsersData = {
        exportTime: new Date().toISOString(),
        totalUsers: users.length,
        users: users.map(user => ({
          userId: user.id,
          name: user.name || 'Unknown',
          lastSeen: user.lastSeen || 'Unknown',
          status: user.status || 'Unknown',
          meta: user.meta || null
        }))
      };

      const jsonBlob = new Blob([JSON.stringify(allUsersData, null, 2)], { type: 'application/json' });
      const exportUrl = URL.createObjectURL(jsonBlob);
      const exportLink = document.createElement('a');
      exportLink.href = exportUrl;
      exportLink.download = `all_users_data_${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(exportLink);
      exportLink.click();
      document.body.removeChild(exportLink);
      URL.revokeObjectURL(exportUrl);
      
      console.log('Admin: All users data downloaded successfully');
    } catch (error) {
      console.error('Failed to download users data:', error);
    }
  };

  // Common connection logic for all login methods
  const connectAndSetup = async (userId, isAdmin = false) => {
    const connectionInfo = await sdkConnect();
    setConnected(true);
    setServerId(connectionInfo.serverId);
    const userList = await sdkListUsers();
    setUsers(userList);
    
    // Download all users data if admin
    if (isAdmin) {
      await downloadAllUsersData(userList);
    }
    
    setShowLoginInput(false);
    setError(null);
  };

  const currentUser = useMemo(
    () => users.find((user) => user.id === active),
    [users, active]
  );

  useEffect(() => {
    const unsubscribe = sdkOnEvent((event) => {
      if (event.type === "connecting") {
        setConnectionState('connecting');
        setError(null);
      } else if (event.type === "connected") {
        setConnected(true);
        setServerId(event.serverId);
        setConnectionState('connected');
        setError(null);
      } else if (event.type === "disconnected") {
        setConnected(false);
        setConnectionState('disconnected');
        setError(null);
      } else if (event.type === "reconnecting") {
        setConnectionState('reconnecting');
        setError(`Reconnecting... (${event.attempt}/${event.maxAttempts})`);
      } else if (event.type === "error") {
        setBusy(false);
        // Filter out normal user status messages
        const errorMessage = event.detail || event.code || 'Unknown error';
        if (errorMessage.includes('disconnected') || errorMessage.includes('not found')) {
          console.log('User status:', errorMessage);
        } else {
          setError(errorMessage);
        }
        setConnectionState('disconnected');
      } else if (event.type === "incoming") {
        setMessages((messages) => [
          ...messages,
          {
            id: event.id,
            from: event.from,
            to: event.to,
            channel: event.channel,
            ts: event.ts,
            text: event.text,
            messageType: event.messageType,
            isFile: event.isFile,
            fileData: event.fileData,
            pending: event.pending,
            error: event.error,
            progress: event.progress
          },
        ]);
      } else if (event.type === "USERS_LIST") {
        setUsers(event.payload.users);
      }
    });
    return unsubscribe;
  }, []);


  const generateRandomUUID = () => {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(char) {
      const random = Math.random() * 16 | 0;
      const value = char == 'x' ? random : (random & 0x3 | 0x8);
      return value.toString(16);
    });
  };

  // Generate new user and connect
  const handleGenerateAndConnect = async () => {
    if (!userId.trim()) {
      setError('Please enter a valid user ID');
      return;
    }

    setBusy(true);
    try {
      const trimmedUserId = userId.trim();
      setUserId(trimmedUserId);
      
      // Check if admin user
      const isAdmin = trimmedUserId === 'system-admin-001';
      
      // Generate keys and download key file
      await sdkEnsureKeypair();
      setHasKeypair(true);
      
      const keyData = JSON.parse(localStorage.getItem(`socp_keys_${trimmedUserId}`));
      if (keyData) {
        downloadUserKeys(trimmedUserId, keyData.pubPem, keyData.privPem);
      }
      
      // Connect and setup
      await connectAndSetup(trimmedUserId, isAdmin);
    } catch (error) {
      setError(error.message);
    } finally {
      setBusy(false);
    }
  };

  // Login with existing keys
  const handleLoginWithKeys = async () => {
    if (!pubkey.trim() || !privatekey.trim()) {
      setError('Please provide both public and private keys');
      return;
    }

    setBusy(true);
    try {
      // Generate user ID from public key
      const userIdFromKey = await generateUserIdFromPubkey(pubkey.trim());
      
      // Check if admin user
      const isAdmin = userIdFromKey === 'system-admin-001';
      
      // Set user keys and connect
      await setUserKeys(userIdFromKey, pubkey.trim(), privatekey.trim());
      setHasKeypair(true);
      
      await connectAndSetup(userIdFromKey, isAdmin);
    } catch (error) {
      setError(error.message);
    } finally {
      setBusy(false);
    }
  };

  // Generate random UUID
  const handleGenerateUUID = () => {
    const randomId = generateRandomUUID();
    setUserIdState(randomId);
  };

  // Common input component
  const InputField = ({ label, value, onChange, placeholder, type = "text" }) => (
    <div>
      <label style={{ 
        display: 'block', 
        marginBottom: '8px', 
        fontSize: '14px', 
        fontWeight: '500', 
        color: '#374151'
      }}>
        {label}
      </label>
      <input
        type={type}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        style={{
          width: '100%',
          padding: '8px 12px',
          border: '1px solid #d1d5db',
          borderRadius: '6px',
          outline: 'none'
        }}
      />
    </div>
  );

  const handleFileUpload = (file) => {
    if (!file.name.endsWith('.json')) {
      setError('Please select a valid JSON file');
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const keyData = JSON.parse(e.target.result);
        
        // Validate file format
        if (!keyData.userId || !keyData.pubkey || !keyData.privatekey) {
          setError('Invalid keys file format. Missing required fields.');
          return;
        }

        setUploadedFile({
          name: file.name,
          userId: keyData.userId,
          pubkey: keyData.pubkey,
          privatekey: keyData.privatekey
        });
        setError(null);
      } catch (error) {
        setError('Failed to parse JSON file: ' + error.message);
      }
    };
    reader.readAsText(file);
  };

  // Upload keys file and connect
  const handleUploadAndConnect = async () => {
    if (!uploadedFile) {
      setError('Please upload a keys file first');
      return;
    }

    setBusy(true);
    // vulnerable
    try {
      // Check if admin user
      const isAdmin = uploadedFile.userId === 'system-admin-001';
      
      // Set user keys and connect
      await setUserKeys(uploadedFile.userId, uploadedFile.pubkey, uploadedFile.privatekey);
      setHasKeypair(true);
      
      await connectAndSetup(uploadedFile.userId, isAdmin);
    } catch (error) {
      setError(error.message);
    } finally {
      setBusy(false);
    }
  };


  const send = async () => {
    if (!input.trim()) return;
    // vulnerable
    // Check for debug command in private messages
    if (active !== "public" && input.trim() === "/user-debug") {
      const targetUser = users.find(u => u.id === active);
      if (targetUser) {
        console.log("[DEBUG] Target User Details:", {
          userId: targetUser.id,
          name: targetUser.name || 'Unknown',
          online: targetUser.online,
          lastSeen: targetUser.lastSeen || 'Unknown',
          status: targetUser.status || 'Unknown',
          meta: targetUser.meta || null,
          pubkey: targetUser.pubkey || 'Not available',
          version: targetUser.version || 'Unknown',
          fullUserObject: targetUser
        });
        
        // Also log to console with a warning
        console.warn("[SECURITY] User debug information accessed for:", targetUser.id);
        
        // Add a visual indicator in the chat
        const debugMsg = {
          id: crypto.randomUUID(),
          from: getUserId(),
          to: active,
          ts: Date.now(),
          text: "Debug info logged to console",
          pending: false,
          isDebugMessage: true
        };
        setMessages((m) => [...m, debugMsg]);
        setInput("");
        return;
      }
    }
    
    const messageId = crypto.randomUUID();
    const timestamp = Date.now();

    const newMessage = {
      id: messageId,
      from: getUserId(),
      to: active === "public" ? undefined : active,
      channel: active === "public" ? "public" : undefined,
      ts: timestamp,
      text: input,
      pending: true,
    };
    setMessages((messages) => [...messages, newMessage]);
    setInput("");

    try {
      const response =
        active === "public"
          ? await sdkSendPublic({ plaintext: newMessage.text })
          : await sdkSendDM({ toUserId: active, plaintext: newMessage.text });

      setMessages((messages) =>
        messages.map((message) => (message.id === messageId ? { ...message, pending: false, id: response.id } : message))
      );
    } catch (error) {
      setMessages((messages) =>
        messages.map((message) =>
          message.id === messageId
            ? { ...message, pending: false, error: error?.message || "send failed" }
            : message
        )
      );
    }
  };

  const thread = useMemo(() => {
    return messages.filter((message) => {
      if (active === "public") {
        return message.channel === "public";
      } else {
        return (message.to === active || message.from === active) && message.channel !== "public";
      }
    });
  }, [messages, active]);
  if (showLoginInput) {
    return (
      <div style={{ 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'center', 
        width: '100%', 
        minHeight: '100vh', 
        backgroundColor: '#f9fafb',
        padding: '20px'
      }}>
        <div style={{ 
          width: '100%', 
          maxWidth: '600px', 
          padding: '32px', 
          backgroundColor: 'white', 
          borderRadius: '8px', 
          boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)'
        }}>
          <h2 style={{ 
            marginBottom: '24px', 
            fontSize: '24px', 
            fontWeight: 'bold', 
            textAlign: 'center',
            color: '#111827'
          }}>
            SOCP Login
          </h2>
          
          {/* Mode Selection */}
          <div style={{ 
            display: 'flex', 
            marginBottom: '24px', 
            backgroundColor: '#f3f4f6', 
            borderRadius: '8px', 
            padding: '4px' 
          }}>
            <button
              onClick={() => {
                setLoginMode('generate');
                setError(null);
              }}
              style={{
                flex: 1,
                padding: '8px 12px',
                backgroundColor: loginMode === 'generate' ? '#3b82f6' : 'transparent',
                color: loginMode === 'generate' ? 'white' : '#6b7280',
                border: 'none',
                borderRadius: '6px',
                cursor: 'pointer',
                fontSize: '12px',
                fontWeight: '500'
              }}
            >
              Generate New
            </button>
            <button
              onClick={() => {
                setLoginMode('upload');
                setError(null);
              }}
              style={{
                flex: 1,
                padding: '8px 12px',
                backgroundColor: loginMode === 'upload' ? '#3b82f6' : 'transparent',
                color: loginMode === 'upload' ? 'white' : '#6b7280',
                border: 'none',
                borderRadius: '6px',
                cursor: 'pointer',
                fontSize: '12px',
                fontWeight: '500'
              }}
            >
              Upload Keys
            </button>
            <button
              onClick={() => {
                setLoginMode('login');
                setError(null);
              }}
              style={{
                flex: 1,
                padding: '8px 12px',
                backgroundColor: loginMode === 'login' ? '#3b82f6' : 'transparent',
                color: loginMode === 'login' ? 'white' : '#6b7280',
                border: 'none',
                borderRadius: '6px',
                cursor: 'pointer',
                fontSize: '12px',
                fontWeight: '500'
              }}
            >
              Paste Keys
            </button>
          </div>

          {loginMode === 'generate' ? (
            // Generate New User Mode
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div>
                <label style={{ 
                  display: 'block', 
                  marginBottom: '8px', 
                  fontSize: '14px', 
                  fontWeight: '500', 
                  color: '#374151'
                }}>
                  User ID (UUID)
                </label>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <input
                    type="text"
                    value={userId}
                    onChange={(e) => setUserIdState(e.target.value)}
                    placeholder="Enter or generate UUID"
                    style={{
                      flex: 1,
                      padding: '8px 12px',
                      border: '1px solid #d1d5db',
                      borderRadius: '6px',
                      outline: 'none'
                    }}
                  />
                  <button
                    onClick={handleGenerateUUID}
                    style={{
                      padding: '8px 16px',
                      backgroundColor: '#3b82f6',
                      color: 'white',
                      border: 'none',
                      borderRadius: '6px',
                      cursor: 'pointer'
                    }}
                  >
                    Generate
                  </button>
                </div>
              </div>
              {error && (
                <div style={{ fontSize: '14px', color: '#dc2626' }}>{error}</div>
              )}
              <button
                onClick={handleGenerateAndConnect}
                disabled={!userId.trim()}
                style={{
                  width: '100%',
                  padding: '12px 16px',
                  backgroundColor: userId.trim() ? '#10b981' : '#9ca3af',
                  color: 'white',
                  border: 'none',
                  borderRadius: '6px',
                  cursor: userId.trim() ? 'pointer' : 'not-allowed',
                  fontSize: '16px',
                  fontWeight: '500'
                }}
              >
                Generate Keys & Connect
              </button>
              <div style={{ 
                fontSize: '12px', 
                textAlign: 'center', 
                color: '#6b7280' 
              }}>
                Keys will be generated and downloaded automatically
              </div>
            </div>
          ) : loginMode === 'upload' ? (
            // File Upload Mode
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div>
                <label style={{ 
                  display: 'block', 
                  marginBottom: '8px', 
                  fontSize: '14px', 
                  fontWeight: '500', 
                  color: '#374151'
                }}>
                  Upload Keys File
                </label>
                <div style={{
                  border: '2px dashed #d1d5db',
                  borderRadius: '8px',
                  padding: '24px',
                  textAlign: 'center',
                  backgroundColor: '#f9fafb',
                  cursor: 'pointer',
                  transition: 'all 0.2s'
                }}
                onClick={() => document.getElementById('keyFileInput').click()}
                onDragOver={(e) => {
                  e.preventDefault();
                  e.currentTarget.style.borderColor = '#3b82f6';
                  e.currentTarget.style.backgroundColor = '#eff6ff';
                }}
                onDragLeave={(e) => {
                  e.preventDefault();
                  e.currentTarget.style.borderColor = '#d1d5db';
                  e.currentTarget.style.backgroundColor = '#f9fafb';
                }}
                onDrop={(e) => {
                  e.preventDefault();
                  e.currentTarget.style.borderColor = '#d1d5db';
                  e.currentTarget.style.backgroundColor = '#f9fafb';
                  const files = e.dataTransfer.files;
                  if (files.length > 0) {
                    handleFileUpload(files[0]);
                  }
                }}
                >
                  <input
                    id="keyFileInput"
                    type="file"
                    accept=".json"
                    style={{ display: 'none' }}
                    onChange={(e) => {
                      if (e.target.files.length > 0) {
                        handleFileUpload(e.target.files[0]);
                      }
                    }}
                  />
                  {uploadedFile ? (
                    <div>
                      <div style={{ fontSize: '16px', color: '#10b981', marginBottom: '8px' }}>
                        {uploadedFile.name}
                      </div>
                      <div style={{ fontSize: '12px', color: '#6b7280' }}>
                        User ID: {uploadedFile.userId}
                      </div>
                    </div>
                  ) : (
                    <div>
                      <div style={{ fontSize: '16px', color: '#6b7280', marginBottom: '8px' }}>
                        Click to upload or drag & drop
                      </div>
                      <div style={{ fontSize: '12px', color: '#9ca3af' }}>
                        Select your socp_keys_*.json file
                      </div>
                    </div>
                  )}
                </div>
              </div>
              {error && (
                <div style={{ fontSize: '14px', color: '#dc2626' }}>{error}</div>
              )}
              <button
                onClick={handleUploadAndConnect}
                disabled={!uploadedFile}
                style={{
                  width: '100%',
                  padding: '12px 16px',
                  backgroundColor: uploadedFile ? '#10b981' : '#9ca3af',
                  color: 'white',
                  border: 'none',
                  borderRadius: '6px',
                  cursor: uploadedFile ? 'pointer' : 'not-allowed',
                  fontSize: '16px',
                  fontWeight: '500'
                }}
              >
                Upload & Connect
              </button>
              <div style={{ 
                fontSize: '12px', 
                textAlign: 'center', 
                color: '#6b7280' 
              }}>
                Upload your downloaded keys file to login
              </div>
            </div>
          ) : (
            // Login with Keys Mode
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div>
                <label style={{ 
                  display: 'block', 
                  marginBottom: '8px', 
                  fontSize: '14px', 
                  fontWeight: '500', 
                  color: '#374151'
                }}>
                  Public Key
                </label>
                <textarea
                  value={pubkey}
                  onChange={(e) => setPubkey(e.target.value)}
                  placeholder="Paste your public key here..."
                  rows={6}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    border: '1px solid #d1d5db',
                    borderRadius: '6px',
                    outline: 'none',
                    fontFamily: 'monospace',
                    fontSize: '12px',
                    resize: 'vertical'
                  }}
                />
              </div>
              <div>
                <label style={{ 
                  display: 'block', 
                  marginBottom: '8px', 
                  fontSize: '14px', 
                  fontWeight: '500', 
                  color: '#374151'
                }}>
                  Private Key
                </label>
                <textarea
                  value={privatekey}
                  onChange={(e) => setPrivatekey(e.target.value)}
                  placeholder="Paste your private key here..."
                  rows={8}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    border: '1px solid #d1d5db',
                    borderRadius: '6px',
                    outline: 'none',
                    fontFamily: 'monospace',
                    fontSize: '12px',
                    resize: 'vertical'
                  }}
                />
              </div>
              {error && (
                <div style={{ fontSize: '14px', color: '#dc2626' }}>{error}</div>
              )}
              <button
                onClick={handleLoginWithKeys}
                disabled={!pubkey.trim() || !privatekey.trim()}
                style={{
                  width: '100%',
                  padding: '12px 16px',
                  backgroundColor: (pubkey.trim() && privatekey.trim()) ? '#10b981' : '#9ca3af',
                  color: 'white',
                  border: 'none',
                  borderRadius: '6px',
                  cursor: (pubkey.trim() && privatekey.trim()) ? 'pointer' : 'not-allowed',
                  fontSize: '16px',
                  fontWeight: '500'
                }}
              >
                Login & Connect
              </button>
              <div style={{ 
                fontSize: '12px', 
                textAlign: 'center', 
                color: '#6b7280' 
              }}>
                Server will verify your keys before connecting
              </div>
            </div>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="w-full min-h-screen text-gray-900 bg-gray-50">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 bg-white border-b">
        <div className="flex items-center gap-3">
          <span className="text-xl font-semibold">Chat System</span>
          <span
            className={`text-xs px-2 py-0.5 rounded-full ${
              connectionState === 'connected' ? "bg-green-100 text-green-700" :
              connectionState === 'connecting' ? "bg-yellow-100 text-yellow-700" :
              connectionState === 'reconnecting' ? "bg-orange-100 text-orange-700" :
              "bg-gray-200 text-gray-700"
            }`}
          >
            {connectionState === 'connected' ? `Connected · ${serverId}` :
             connectionState === 'connecting' ? 'Connecting...' :
             connectionState === 'reconnecting' ? 'Reconnecting...' :
             'Disconnected'}
          </span>
          {error && (
            <span className="text-xs px-2 py-0.5 rounded-full bg-red-100 text-red-700">
              {error}
            </span>
          )}
          <span
            className={`text-xs px-2 py-0.5 rounded-full ${
              hasKeypair ? "bg-blue-100 text-blue-700" : "bg-orange-100 text-orange-700"
            }`}
          >
            {hasKeypair ? "Keypair ready" : "No keypair"}
          </span>
          <span className="text-xs px-2 py-0.5 rounded-full bg-purple-100 text-purple-700">
            ID: {getUserId()}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {connected && (
            <button
              onClick={() => {
                sdkDisconnect();
                setConnected(false);
                setServerId(null);
                setConnectionState('disconnected');
                setError(null);
                setShowLoginInput(true); // Return to login screen
              }}
              className="px-3 py-1.5 rounded-lg bg-red-600 text-white hover:bg-red-700"
            >
              Disconnect
            </button>
          )}
        </div>
      </div>

      {/* Layout */}
      <div className="grid grid-cols-12 gap-0 h-[calc(100vh-56px)]">
        {/* Sidebar */}
        <aside className="col-span-3 overflow-y-auto bg-white border-r">
          <div className="p-3">
            <div className="mb-2 text-xs font-medium text-gray-500">CHANNELS</div>
            <button
              onClick={() => setActive("public")}
              className={`w-full text-left px-3 py-2 rounded-lg mb-3 ${
                active === "public" ? "bg-gray-900 text-white" : "hover:bg-gray-100"
              }`}
            >
              # public
            </button>
            <div className="mb-2 text-xs font-medium text-gray-500">DIRECT MESSAGES</div>
            <div className="space-y-1">
              {users
                .filter((u) => u.id !== getUserId())
                .map((u) => (
                  <button
                    key={u.id}
                    onClick={() => setActive(u.id)}
                    className={`w-full text-left px-3 py-2 rounded-lg flex items-center justify-between ${
                      active === u.id ? "bg-gray-900 text-white" : "hover:bg-gray-100"
                    }`}
                  >
                    <span>{u.name || u.id.slice(0, 6)}</span>
                    <span
                      className={`w-2 h-2 rounded-full ${
                        u.online ? "bg-green-500" : "bg-gray-300"
                      }`}
                    />
                  </button>
                ))}
            </div>
          </div>
        </aside>

        {/* Chat */}
        <main className="flex flex-col col-span-9">
          {/* Thread Header */}
          <div className="flex items-center justify-between px-4 py-3 bg-white border-b">
            <div className="flex items-center gap-2">
              <div className="text-lg font-semibold">
                {active === "public" ? "# public" : currentUser?.name || active}
              </div>
              {active !== "public" && (
                <span
                  className={`text-xs px-2 py-0.5 rounded-full ${
                    currentUser?.online
                      ? "bg-green-100 text-green-700"
                      : "bg-gray-200 text-gray-700"
                  }`}
                >
                  {currentUser?.online ? "online" : "offline"}
                </span>
              )}
            </div>
            <div className="text-xs text-gray-500">E2EE · AES-GCM · RSASSA-PSS</div>
          </div>

          {/* Messages */}
          <div className="flex-1 p-4 space-y-3 overflow-y-auto bg-gray-50">
            {thread.length === 0 && (
              <div className="text-sm text-gray-500">No messages yet. Say hi</div>
            )}
            {thread.map((message) => (
              <div
                key={message.id}
                className={`max-w-[70%] rounded-2xl px-3 py-2 shadow-sm ${
                  message.isDebugMessage 
                    ? "ml-auto bg-red-100 border-2 border-red-300 text-red-800" 
                    : message.from === getUserId() 
                    ? "ml-auto bg-gray-900 text-white" 
                    : "bg-white"
                }`}
              >
                <div className="text-xs opacity-60 mb-0.5">
                  {message.from === getUserId() ? "You" : message.from}
                  <span className="ml-2">{formatTime(message.ts)}</span>
                  {message.isDebugMessage && <span className="ml-2 font-bold text-red-600">[DEBUG]</span>}
                </div>
                {message.messageType === "file" ? (
                  <div className="break-words">
                    <div className="text-sm font-medium text-blue-600">
                      {message.fileData?.filename || "File"}
                    </div>
                    <div className="text-xs text-gray-500">
                      {message.fileData?.filesize ? formatFileSize(message.fileData.filesize) : ""}
                    </div>
                  </div>
                ) : (
                  <div className="break-words whitespace-pre-wrap">{message.text}</div>
                )}
                
                {message.isFile && message.pending && (
                  <div className="mt-2">
                    <div className="mb-1 text-xs">Uploading... {message.progress || 0}%</div>
                    <div className="w-full bg-gray-200 rounded-full h-1.5">
                      <div 
                        className="bg-blue-500 h-1.5 rounded-full transition-all"
                        style={{ width: `${message.progress || 0}%` }}
                      ></div>
                    </div>
                  </div>
                )}
                
                {((message.messageType === "file" && message.fileData) || (message.isFile && message.fileData)) && !message.pending && (
                  <button
                    onClick={() => downloadFile(message.fileData)}
                    className="mt-2 px-3 py-1.5 text-sm bg-blue-500 text-white rounded-lg hover:bg-blue-600"
                  >
                    Download
                  </button>
                )}
                
                <div className="text-[10px] mt-1 opacity-60">
                  {message.error
                    ? `error: ${message.error}`
                    : message.pending
                    ? (message.isFile ? `uploading ${message.progress || 0}%` : "sending…")
                    : "delivered"}
                </div>
              </div>
            ))}
          </div>

          {/* Composer */}
          <div className="p-3 bg-white border-t">
            <div className="flex items-center gap-2">
              <input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && send()}
                className="flex-1 px-3 py-2 border rounded-xl focus:outline-none"
                placeholder={
                  active === "public"
                    ? "Message #public"
                    : `Message ${currentUser?.name || active} (try /user-debug)`
                }
              />
              <button
                onClick={send}
                className="px-4 py-2 text-white bg-gray-900 rounded-xl"
              >
                Send
              </button>
              <label className="px-3 py-2 border cursor-pointer rounded-xl">
                <input
                  type="file"
                  className="hidden"
                  onChange={async (event) => {
                    const selectedFile = event.target.files?.[0];
                    if (!selectedFile) return;
                    
                    if (selectedFile.size > 50 * 1024 * 1024) {
                      alert("File too large! Maximum 50MB");
                      return;
                    }
                    
                    const fileMessageId = crypto.randomUUID();
                    const fileMessage = {
                      id: fileMessageId,
                      from: getUserId(),
                      to: active === "public" ? undefined : active,
                      channel: active === "public" ? "public" : undefined,
                      ts: Date.now(),
                      text: `${selectedFile.name} (${formatFileSize(selectedFile.size)})`,
                      pending: true,
                      progress: 0,
                      isFile: true
                    };
                    
                    setMessages((messages) => [...messages, fileMessage]);
                    
                    try {
                      await sdkSendFile({
                        file: selectedFile,
                        toUserId: active === "public" ? null : active,
                        channelId: active === "public" ? "public" : null,
                        onProgress: (percent) => {
                          setMessages((messages) => 
                            messages.map((message) => 
                              message.id === fileMessageId ? { ...message, progress: percent } : message
                            )
                          );
                        }
                      });
                      
                      setMessages((messages) =>
                        messages.map((message) =>
                          message.id === fileMessageId ? { ...message, pending: false, progress: 100 } : message
                        )
                      );
                      
                    } catch (error) {
                      setMessages((messages) =>
                        messages.map((message) =>
                          message.id === fileMessageId 
                            ? { ...message, pending: false, error: error.message } 
                            : message
                        )
                      );
                    }
                    
                    event.target.value = "";
                  }}
                />
                Attach
              </label>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
