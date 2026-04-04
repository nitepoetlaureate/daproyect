import { useState } from 'react';

function ScanForm({ onSubmit, isScanning }) {
  const [target, setTarget] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!target) {
      alert('Please enter a target.');
      return;
    }
    onSubmit(target);
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="text"
        value={target}
        onChange={(e) => setTarget(e.target.value)}
        placeholder="e.g., 192.168.1.0/24"
        disabled={isScanning}
      />
      <button type="submit" disabled={isScanning}>
        {isScanning ? 'Scanning...' : 'Start Scan'}
      </button>
    </form>
  );
}

export default ScanForm;
