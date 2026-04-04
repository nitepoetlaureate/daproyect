function LogViewer({ logs }) {
  return (
    <pre className="log-viewer">
      {logs.join('\n')}
    </pre>
  );
}

export default LogViewer;
