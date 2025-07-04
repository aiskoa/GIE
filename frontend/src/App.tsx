import { useState, useEffect } from 'react';
import './App.css';
import { IsDirectory, SelectFile, SelectDirectory, EncryptFile, DecryptFile, EncryptDirectory, DecryptDirectory, GetHint, OpenExternalURL } from '../wailsjs/go/main/App';
import { OnFileDrop } from '../wailsjs/runtime/runtime';
import fileIcons from './assets/file-icons.json';
import logo from './assets/images/logo.png';
import folderIcon from './assets/images/folder.svg';

// Helper to clean up file paths that might have prefixes
const normalizePath = (path: string): string => {
    if (path.startsWith('file://')) {
        return path.substring(7);
    }
    return path;
};

function App() {
    const [password, setPassword] = useState('');
    const [hint, setHint] = useState('');
    const [filePath, setFilePath] = useState('');
    const [isProcessing, setIsProcessing] = useState(false);
    const [isDragOver, setIsDragOver] = useState(false);
    const [isDirectory, setIsDirectory] = useState(false);
    const [fileName, setFileName] = useState('');
    const [status, setStatus] = useState('Drop your Files or Folders Here!');
    const [showAdvancedOptions, setShowAdvancedOptions] = useState(false);
    const [encryptionLevel, setEncryptionLevel] = useState('Normal');
    const [channel, setChannel] = useState(50);
    const [isEncryptedFile, setIsEncryptedFile] = useState(false);
    const [showPassword, setShowPassword] = useState(false);

    useEffect(() => {
        OnFileDrop(async (x, y, paths) => {
            if (paths.length > 0) {
                const normalizedPath = normalizePath(paths[0]);
                handleFileSelect(normalizedPath);
            }
        }, false);
    }, []);

    const handleFileSelect = async (path: string) => {
        const normalizedPath = normalizePath(path);
        setFilePath(normalizedPath);
        const isDir = await IsDirectory(normalizedPath);
        setIsDirectory(isDir);
        setFileName(normalizedPath.split(/[\\/]/).pop() || '');
        setStatus(''); // Clear status on new file

        if (!isDir && normalizedPath.toLowerCase().endsWith('.gie')) {
            setIsEncryptedFile(true);
            try {
                const fileHint = await GetHint(normalizedPath);
                setHint(fileHint || '');
            } catch (error) {
                console.error("Error getting hint:", error);
                setHint('');
            }
        } else {
            setIsEncryptedFile(false);
            setHint('');
            setChannel(50); // Reset channel to default for new files
        }
    };

    const openFileSelector = async () => {
        try {
            const selectedPath = await SelectFile();
            if (selectedPath) {
                handleFileSelect(selectedPath);
            }
        } catch (error) {
            //setStatus(`Error: ${error}`);
        }
    };

    const openDirectorySelector = async () => {
        try {
            const selectedPath = await SelectDirectory();
            if (selectedPath) {
                handleFileSelect(selectedPath);
            }
        } catch (error) {
            //setStatus(`Error: ${error}`);
        }
    };

    const handleEncrypt = async () => {
        if (!filePath || !password.trim()) {
            setStatus('Please provide a file and a password.');
            return;
        }
        setIsProcessing(true);
        setStatus('Encrypting...');
        try {
            const response = isDirectory
                ? await EncryptDirectory(filePath, password, hint, encryptionLevel, channel)
                : await EncryptFile(filePath, password, hint, encryptionLevel, channel);
            setStatus(response.includes("completed") ? 'Encryption Successful!' : `Done: ${response}`);
            setTimeout(resetState, 2000);
        } catch (error) {
            setStatus(`Encryption failed: ${error}`);
        } finally {
            setIsProcessing(false);
        }
    };

    const handleDecrypt = async () => {
        if (!filePath || !password.trim()) {
            setStatus('Please provide a file and a password.');
            return;
        }
        setIsProcessing(true);
        setStatus('Decrypting...');
        try {
            const response = isDirectory
                ? await DecryptDirectory(filePath, password, channel)
                : await DecryptFile(filePath, password, false, channel);
            setStatus(response.includes("completed") ? 'Decryption Successful!' : `Done: ${response}`);
            setTimeout(resetState, 2000);
        } catch (error) {
            setStatus(`Decryption failed: ${error}`);
        } finally {
            setIsProcessing(false);
        }
    };
    
    const resetState = () => {
        setFilePath('');
        setPassword('');
        setHint('');
        setFileName('');
        setIsDirectory(false);
        setStatus('Drop your Files or Folders Here!');
        setShowAdvancedOptions(false);
        setIsEncryptedFile(false);
        setShowPassword(false);
    };

    const getFileIcon = (fileName: string) => {
        const extension = fileName.split('.').pop()?.toLowerCase() || '';
        const iconFileName = (fileIcons.mappings as Record<string, string>)[extension] || fileIcons.default;
        return new URL(`./assets/images/icons/${iconFileName}`, import.meta.url).href;
    };

    const renderInitialView = () => (
        <div>
            <div
                className={`drop-zone ${isDragOver ? 'drag-over' : ''}`}
                onDragOver={(e) => { e.preventDefault(); setIsDragOver(true); }}
                onDragLeave={() => setIsDragOver(false)}
                onDrop={(e) => { 
                    e.preventDefault(); 
                    setIsDragOver(false); 
                    // The OnFileDrop in useEffect will handle the dropped files
                }}
            >
                <div className="drop-icon">↓</div>
                <div className="drop-message">{status}</div>
            </div>
            <div className="manual-selection-group">
                <button onClick={openFileSelector} className="manual-button">📄 Add File</button>
                <button onClick={openDirectorySelector} className="manual-button">📂 Add Directory</button>
            </div>
            <br />
            <div className="help-section">
            <a href="#" onClick={() =>  OpenExternalURL("https://gie-aiskoa.vercel.app")} style={{ color: '#fefebc' }}>¿Need help?</a>  
                <span style={{ margin: '0 10px' }}>|</span>
                <a href="#" onClick={() =>  OpenExternalURL("https://aiskoa.vercel.app")} style={{ color: '#fefebc' }}>Made by ♛AISKOA</a>  
            </div>
        </div>
    );

    const renderFileView = () => (
        <div className="file-view">
            <img src={isDirectory ? folderIcon : getFileIcon(fileName)} alt="icon" className="file-icon" draggable="false"/>
            <div className="file-name">{fileName}</div>
            
            <div className="password-wrapper">
                <input
                    type={showPassword ? 'text' : 'password'}
                    className="input-field"
                    placeholder="Password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    disabled={isProcessing}
                />
                <span className="password-eye" onClick={() => setShowPassword(!showPassword)}>
                    {showPassword ? '🙈' : '👁️'}
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

            <div className="advanced-options-toggle" onClick={() => setShowAdvancedOptions(!showAdvancedOptions)}>
                {showAdvancedOptions ? 'Hide' : 'Show'} Advanced Options
            </div>

            {showAdvancedOptions && (
                <div className="advanced-options">

                    <div className="input-label">Encryption Level:</div>

                    <select 
                        className="input-field"
                        value={encryptionLevel}
                        onChange={(e) => setEncryptionLevel(e.target.value)}
                        disabled={isEncryptedFile}
                    >
                        <option value="Low">Low</option>
                        <option value="Normal">Normal</option>
                        <option value="High">High</option>
                    </select>

                    <div className="input-label">Channel:</div>

                    <input
                        type="number"
                        className="input-field"
                        placeholder="Channel"
                        value={channel}
                        onChange={(e) => setChannel(parseInt(e.target.value, 10))}
                        disabled={isProcessing}
                    />
                </div>
            )}

            <div className="button-group">
                <button onClick={resetState} className="cancel-button" disabled={isProcessing}>Cancel</button>
                <button onClick={handleEncrypt} className="action-button" disabled={isProcessing || !password || isEncryptedFile}>Encrypt</button>
            </div>
             <div className="button-group">
                <button onClick={handleDecrypt} className="action-button secondary" disabled={isProcessing || !password}>Decrypt</button>
            </div>
            
            {isProcessing && <div className="status-message">Processing...</div>}
            {isProcessing && (
                <div className="processing-overlay">
                    <div className="spinner"></div>
                    <div className="processing-text">Processing...</div>
                </div>
            )}
            {status && !isProcessing && <div className="status-message">{status}</div>}
        </div>
    );

    return (
        <div id="App">
            <div className="container">
                <div className="header">
                    {/* <h1>GIE</h1> */}
                    <img src={logo} alt="logo" className="gie-logo" style={{width: '170px'}} draggable="false" />
                    <h3 className="btn-shine">Encrypt your files easily</h3>
                </div>
                {filePath ? renderFileView() : renderInitialView()}
            </div>
        </div>
    );
}

export default App;
