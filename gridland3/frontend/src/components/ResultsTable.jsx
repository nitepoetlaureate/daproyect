const isUrl = (str) => {
  if (typeof str !== 'string') return false;
  return str.startsWith('http://') || str.startsWith('https://') || str.startsWith('rtsp://');
};

const RenderableCell = ({ content }) => {
  if (isUrl(content)) {
    return <a href={content} target="_blank" rel="noopener noreferrer">{content}</a>;
  }
  if (typeof content === 'object' && content !== null) {
    return <pre>{JSON.stringify(content, null, 2)}</pre>;
  }
  return String(content);
};


function ResultsTable({ results }) {
  if (results.length === 0) {
    return <p>No results yet.</p>;
  }

  return (
    <table>
      <thead>
        <tr>
          <th>Category</th>
          <th>Description</th>
          <th>Confidence</th>
          <th>Evidence</th>
        </tr>
      </thead>
      <tbody>
        {results.map((result, index) => (
          <tr key={index}>
            <td>{result.category}</td>
            <td><RenderableCell content={result.description} /></td>
            <td>{result.confidence}</td>
            <td><RenderableCell content={result.raw_evidence} /></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default ResultsTable;
