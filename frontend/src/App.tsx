import { useState, useEffect } from "react";
import "./App.css";
import {
  IsDirectory,
  SelectFile,
  SelectDirectory,
  EncryptFile,
  DecryptFile,
  EncryptDirectory,
  DecryptDirectory,
  GetHint,
  OpenExternalURL,
  GetSettings,
  SetTheme,
  SetDeleteOriginal,
  GetAvailableEncryptionMethods,
  UpdateSettings,
  UpdateChannel,
} from "../wailsjs/go/main/App";
import { OnFileDrop, EventsOn } from "../wailsjs/runtime/runtime";
import fileIcons from "./assets/file-icons.json";
import logo from "./assets/images/logo.png";
import logo_app from "./assets/images/logo_app.png";
import folderIcon from "./assets/images/folder.svg";

const normalizePath = (path: string): string => {
  if (path.startsWith("file://")) {
    return path.substring(7);
  }
  return path;
};

// Theme definitions
const themes = {
  dark: {
    name: "Dark",
    colors: {
      background: "#2a2a2a",
      primary: "#ffc107",
      text: "#ffffffe5",
      inputBg: "#3a3f47",
      border: "#4a4f57",
      buttonSecondary: "#5a5f67",
    },
  },
  light: {
    name: "Light",
    colors: {
      background: "#f5f5f5",
      primary: "#2196f3",
      text: "#333333",
      inputBg: "#ffffff",
      border: "#cccccc",
      buttonSecondary: "#e0e0e0",
    },
  },
  scarlet: {
    name: "Scarlet Red",
    colors: {
      background: "#1a0000",
      primary: "#ff4444",
      text: "#ffeeee",
      inputBg: "#330000",
      border: "#660000",
      buttonSecondary: "#440000",
    },
  },
  blue: {
    name: "Transparent Blue",
    colors: {
      background: "rgba(20, 0, 40, 0.95)",
      primary: "#9c27b0",
      text: "#f3e5f5",
      inputBg: "rgba(50, 0, 100, 0.7)",
      border: "rgba(100, 0, 200, 0.5)",
      buttonSecondary: "rgba(80, 0, 160, 0.6)",
    },
  },
};

function App() {
  const [password, setPassword] = useState("");
  const [hint, setHint] = useState("");
  const [filePath, setFilePath] = useState("");
  const [isProcessing, setIsProcessing] = useState(false);
  const [isDragOver, setIsDragOver] = useState(false);
  const [isDirectory, setIsDirectory] = useState(false);
  const [fileName, setFileName] = useState("");
  const [status, setStatus] = useState("Drop your Files or Folders Here!");
  const [showAdvancedOptions, setShowAdvancedOptions] = useState(false);
  const [encryptionLevel, setEncryptionLevel] = useState("Normal");
  const [channel, setChannel] = useState(50);
  const [isEncryptedFile, setIsEncryptedFile] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [currentTheme, setCurrentTheme] = useState("dark");
  const [encryptionMethod, setEncryptionMethod] = useState("AES-CTR");
  const [deleteOriginal, setDeleteOriginalState] = useState(false);
  const [availableEncryptionMethods, setAvailableEncryptionMethods] = useState<
    string[]
  >([]);
  const [progress, setProgress] = useState(0);
  const [canCancel, setCanCancel] = useState(false);
  const [operationId, setOperationId] = useState<string | null>(null);

  useEffect(() => {
    // Load settings on startup
    loadSettings();
    loadEncryptionMethods();

    // Set up file drop handler
    OnFileDrop(async (x, y, paths) => {
      if (paths.length > 0) {
        const normalizedPath = normalizePath(paths[0]);
        handleFileSelect(normalizedPath);
      }
    }, false);

    // Listen for file association events
    EventsOn("wails:open:gie", (filePath: string) => {
      handleFileSelect(filePath);
    });

    // Listen for real progress updates from backend
    EventsOn("encryption:progress", (progressData: any) => {
      console.log("Progress event received:", progressData);
      setProgress(Math.round(progressData.Percentage));
      setStatus(progressData.Stage || "Processing...");
    });

    // Listen for system notifications
    EventsOn("system:notification", (notificationData: any) => {
      showSystemNotification(notificationData.title, notificationData.message);
    });

    // Listen for custom notifications from backend
    EventsOn("notification", (notificationData: any) => {
      showNotification(notificationData);
    });

    // Listen for operation cancellation
    EventsOn("operation:cancel", () => {
      setCanCancel(false);
      setIsProcessing(false);
      setProgress(0);
      setStatus("Operation cancelled");
    });
  }, []); // Solo ejecutar una vez al montar el componente

  useEffect(() => {
    // Apply theme to CSS variables
    const theme = themes[currentTheme as keyof typeof themes];
    if (theme) {
      const root = document.documentElement;
      Object.entries(theme.colors).forEach(([key, value]) => {
        root.style.setProperty(
          `--${key.replace(/([A-Z])/g, "-$1").toLowerCase()}-color`,
          value
        );
      });
    }
  }, [currentTheme]);

  const loadSettings = async () => {
    try {
      const settings = await GetSettings();
      // Only preserve theme from saved settings
      setCurrentTheme(settings.theme || "dark");
      // Always use defaults for these settings
      setDeleteOriginalState(false);
      setEncryptionMethod("AES-CTR");
      setEncryptionLevel("Normal");
      setChannel(50);
    } catch (error) {
      console.error("Error loading settings:", error);
      // Set defaults if error loading
      setCurrentTheme("dark");
      setDeleteOriginalState(false);
      setEncryptionMethod("AES-CTR");
      setEncryptionLevel("Normal");
      setChannel(50);
    }
  };

  const loadEncryptionMethods = async () => {
    try {
      const methods = await GetAvailableEncryptionMethods();
      setAvailableEncryptionMethods(methods);
    } catch (error) {
      console.error("Error loading encryption methods:", error);
      setAvailableEncryptionMethods(["AES-CTR"]);
    }
  };

  const handleThemeChange = async (theme: string) => {
    setCurrentTheme(theme);
    try {
      await SetTheme(theme);
    } catch (error) {
      console.error("Error saving theme:", error);
    }
  };

  const handleDeleteOriginalChange = async (value: boolean) => {
    setDeleteOriginalState(value);
    try {
      await SetDeleteOriginal(value);
    } catch (error) {
      console.error("Error saving delete original setting:", error);
    }
  };

  const handleEncryptionMethodChange = async (method: string) => {
    setEncryptionMethod(method);
    try {
      // Update settings to save the selected method
      const currentSettings = await GetSettings();
      const updatedSettings = {
        ...currentSettings,
        defaultEncryption: method,
      };
      await UpdateSettings(updatedSettings);
    } catch (error) {
      console.error("Error saving encryption method:", error);
    }
  };

  const handleFileSelect = async (path: string) => {
    const normalizedPath = normalizePath(path);
    setFilePath(normalizedPath);
    const isDir = await IsDirectory(normalizedPath);
    setIsDirectory(isDir);
    setFileName(normalizedPath.split(/[\\/]/).pop() || "");
    setStatus("");

    if (!isDir && normalizedPath.toLowerCase().endsWith(".gie")) {
      setIsEncryptedFile(true);
      try {
        const fileHint = await GetHint(normalizedPath);
        setHint(fileHint || "");
      } catch (error) {
        console.error("Error getting hint:", error);
        setHint("");
      }
    } else {
      setIsEncryptedFile(false);
      setHint("");
    }
  };

  const openFileSelector = async () => {
    try {
      const selectedPath = await SelectFile();
      if (selectedPath) {
        handleFileSelect(selectedPath);
      }
    } catch (error) {
      console.error("Error selecting file:", error);
    }
  };

  const openDirectorySelector = async () => {
    try {
      const selectedPath = await SelectDirectory();
      if (selectedPath) {
        handleFileSelect(selectedPath);
      }
    } catch (error) {
      console.error("Error selecting directory:", error);
    }
  };

  const validateChannel = () => {
    if (channel < 0 || channel > 65535) {
      setStatus("Channel must be between 0 and 65535");
      return false;
    }
    return true;
  };

  const handleEncrypt = async () => {
    if (!filePath || !password.trim()) {
      setStatus("Please provide a file and a password.");
      return;
    }

    if (!validateChannel()) {
      return;
    }

    setIsProcessing(true);
    setCanCancel(true);
    setProgress(0);
    setStatus("Initializing encryption...");

    try {
      const response = isDirectory
        ? await EncryptDirectory(
            filePath,
            password,
            hint,
            encryptionLevel,
            channel,
            encryptionMethod,
            deleteOriginal
          )
        : await EncryptFile(
            filePath,
            password,
            hint,
            encryptionLevel,
            channel,
            encryptionMethod,
            deleteOriginal
          );

      setProgress(100);
      setStatus(
        response.includes("completed")
          ? "Encryption Successful!"
          : `Done: ${response}`
      );

      setTimeout(() => {
        resetState();
        setProgress(0);
      }, 2000);
    } catch (error) {
      setProgress(0);
      setStatus(`Encryption failed: ${error}`);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleDecrypt = async () => {
    if (!filePath || !password.trim()) {
      setStatus("Please provide a file and a password.");
      return;
    }

    if (!validateChannel()) {
      return;
    }

    setIsProcessing(true);
    setProgress(0);
    setStatus("Initializing decryption...");

    try {
      const response = isDirectory
        ? await DecryptDirectory(filePath, password)
        : await DecryptFile(filePath, password, false);

      setProgress(100);
      setStatus(
        response.includes("completed")
          ? "Decryption Successful!"
          : `Done: ${response}`
      );

      setTimeout(() => {
        resetState();
        setProgress(0);
      }, 2000);
    } catch (error) {
      setProgress(0);
      setStatus(`Decryption failed: ${error}`);
    } finally {
      setIsProcessing(false);
    }
  };

  const resetState = () => {
    setFilePath("");
    setPassword("");
    setHint("");
    setFileName("");
    setIsDirectory(false);
    setStatus("Drop your Files or Folders Here!");
    setShowAdvancedOptions(false);
    setIsEncryptedFile(false);
    setShowPassword(false);
    setProgress(0);
  };

  const getFileIcon = (fileName: string) => {
    const extension = fileName.split(".").pop()?.toLowerCase() || "";
    const iconFileName =
      (fileIcons.mappings as Record<string, string>)[extension] ||
      fileIcons.default;
    return new URL(`./assets/images/icons/${iconFileName}`, import.meta.url)
      .href;
  };

  // System notification function
  const showSystemNotification = (title: string, message: string) => {
    if ("Notification" in window) {
      if (Notification.permission === "granted") {
        new Notification(title, {
          body: message,
          icon: logo_app,
          badge: logo_app,
        });
      } else if (Notification.permission !== "denied") {
        Notification.requestPermission().then((permission) => {
          if (permission === "granted") {
            new Notification(title, {
              body: message,
              icon: logo_app,
              badge: logo_app,
            });
          }
        });
      }
    }
  };

  // Custom notification function for backend notifications
  const showNotification = (notificationData: any) => {
    const { type, title, message, duration = 5000 } = notificationData;

    // Show system notification
    showSystemNotification(title, message);

    // Also update the status message in the UI
    if (type === "success") {
      setStatus(`✅ ${message}`);
    } else if (type === "error") {
      setStatus(`❌ ${message}`);
    } else {
      setStatus(message);
    }

    // Clear status after duration (always clear, regardless of processing state)
    setTimeout(() => {
      setStatus("");
    }, duration);
  };

  // Cancel operation function
  const handleCancelOperation = async () => {
    try {
      // Import the CancelOperation function
      const { CancelOperation } = await import("../wailsjs/go/main/App");
      await CancelOperation();
      setCanCancel(false);
      setIsProcessing(false);
      setProgress(0);
      setStatus("Operation cancelled by user");
    } catch (error) {
      console.error("Error cancelling operation:", error);
    }
  };

  const renderThemeSelector = () => (
    <div className="theme-selector">
      {Object.entries(themes).map(([key, theme]) => (
        <div
          key={key}
          className={`theme-circle ${currentTheme === key ? "active" : ""}`}
          style={{ backgroundColor: theme.colors.primary }}
          onClick={() => handleThemeChange(key)}
          title={theme.name}
        />
      ))}
    </div>
  );

  const renderInitialView = () => (
    <div>
      <div
        className={`drop-zone ${isDragOver ? "drag-over" : ""}`}
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragOver(true);
        }}
        onDragLeave={() => setIsDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setIsDragOver(false);
        }}
      >
        <div className="drop-icon">↓</div>
        <div className="drop-message">{status}</div>
      </div>
      <div className="manual-selection-group">
        <button onClick={openFileSelector} className="manual-button">
          📄 Add File
        </button>
        <button onClick={openDirectorySelector} className="manual-button">
          📂 Add Directory
        </button>
      </div>
      <br />
      <div className="help-section">
        <a
          href="#"
          onClick={() => OpenExternalURL("https://gie-aiskoa.vercel.app")}
          style={{ color: "var(--primary-color)" }}
        >
          ¿Need help?
        </a>
        <span style={{ margin: "0 10px" }}>|</span>
        <a
          href="#"
          onClick={() => OpenExternalURL("https://aiskoa.vercel.app")}
          style={{ color: "var(--primary-color)" }}
        >
          Made by ♛AISKOA
        </a>
      </div>
    </div>
  );

  const renderFileView = () => (
    <div className="file-view">
      <img
        src={isDirectory ? folderIcon : getFileIcon(fileName)}
        alt="icon"
        className="file-icon"
        draggable="false"
      />
      <div className="file-name">{fileName}</div>

      <div className="password-wrapper">
        <input
          type={showPassword ? "text" : "password"}
          className="input-field"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          disabled={isProcessing}
        />
        <span
          className="password-eye"
          onClick={() => setShowPassword(!showPassword)}
        >
          {showPassword ? "🙈" : "👁️"}
        </span>
      </div>
      <input
        type="text"
        className="input-field"
        placeholder="Hint (optional)"
        value={hint}
        onChange={(e) => setHint(e.target.value)}
        disabled={isProcessing || isEncryptedFile}
      />

      <div
        className="advanced-options-toggle"
        onClick={() => setShowAdvancedOptions(!showAdvancedOptions)}
      >
        {showAdvancedOptions ? "Hide" : "Show"} Advanced Options
      </div>

      {showAdvancedOptions && (
        <div className="advanced-options">
          <div className="input-label">Encryption Method:</div>
          <select
            className="input-field"
            value={encryptionMethod}
            onChange={(e) => handleEncryptionMethodChange(e.target.value)}
            disabled={isEncryptedFile || isProcessing}
          >
            {availableEncryptionMethods.map((method) => (
              <option key={method} value={method}>
                {method}
              </option>
            ))}
          </select>

          <div className="input-label">Encryption Level:</div>
          <select
            className="input-field"
            value={encryptionLevel}
            onChange={(e) => setEncryptionLevel(e.target.value)}
            disabled={isEncryptedFile || isProcessing}
          >
            <option value="Low">Low (Fast)</option>
            <option value="Normal">Normal (Balanced)</option>
            <option value="High">High (Secure)</option>
          </select>

          <div className="input-label">Channel (0-65535):</div>
          <input
            type="number"
            className="input-field"
            placeholder="Channel"
            value={channel}
            min="0"
            max="65535"
            onChange={async (e) => {
              const value = parseInt(e.target.value, 10);
              if (!isNaN(value)) {
                const newChannel = Math.max(0, Math.min(65535, value));
                setChannel(newChannel);
                // Update backend with new channel
                try {
                  await UpdateChannel(newChannel);
                } catch (error) {
                  console.error("Error updating channel:", error);
                }
              }
            }}
            disabled={isProcessing}
          />

          <div className="checkbox-wrapper">
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={deleteOriginal}
                onChange={(e) => handleDeleteOriginalChange(e.target.checked)}
                disabled={isProcessing || isEncryptedFile}
              />
              <span className="checkmark"></span>
              Delete Original File?
            </label>
          </div>
        </div>
      )}

      <div className="button-group">
        <button
          onClick={resetState}
          className="cancel-button"
          disabled={isProcessing}
        >
          Cancel
        </button>
        <button
          onClick={handleEncrypt}
          className="action-button"
          disabled={isProcessing || !password || isEncryptedFile}
        >
          Encrypt
        </button>
      </div>
      <div className="button-group">
        <button
          onClick={handleDecrypt}
          className="action-button secondary"
          disabled={isProcessing || !password}
        >
          Decrypt
        </button>
      </div>

      {isProcessing && (
        <div className="processing-overlay">
          <div className="progress-container">
            <div className="progress-circle">
              <svg className="progress-ring" width="80" height="80">
                <circle
                  className="progress-ring-circle"
                  stroke="var(--primary-color)"
                  strokeWidth="4"
                  fill="transparent"
                  r="36"
                  cx="40"
                  cy="40"
                  style={{
                    strokeDasharray: `${2 * Math.PI * 36}`,
                    strokeDashoffset: `${
                      2 * Math.PI * 36 * (1 - progress / 100)
                    }`,
                    transition: "stroke-dashoffset 0.3s ease",
                  }}
                />
              </svg>
              <div className="progress-text">{Math.round(progress)}%</div>
            </div>
            <div className="processing-text">{status}</div>
            {canCancel && (
              <button
                onClick={handleCancelOperation}
                className="cancel-operation-button"
              >
                Cancel
              </button>
            )}
          </div>
        </div>
      )}
      {status && !isProcessing && (
        <div className="status-message">{status}</div>
      )}
    </div>
  );

  return (
    <div id="App" className={`theme-${currentTheme}`}>
      <div className="container">
        <div className="header">
          {renderThemeSelector()}
          <img
            src={logo}
            alt="logo"
            className="gie-logo"
            style={{ width: "170px" }}
            draggable="false"
          />
          <h3 className="btn-shine">Encrypt your files easily</h3>
        </div>
        {filePath ? renderFileView() : renderInitialView()}
      </div>
    </div>
  );
}

export default App;
