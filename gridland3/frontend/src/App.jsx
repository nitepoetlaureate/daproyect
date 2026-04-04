import React, { useEffect, useState } from 'react';
import mapboxgl from 'mapbox-gl';
import 'mapbox-gl/dist/mapbox-gl.css';

// HARD-CODED TOKEN FOR THE BUILD
const MAPBOX_TOKEN = import.meta.env.VITE_MAPBOX_TOKEN || "YOUR_MAPBOX_TOKEN";

function App() {
  const [nodes, setNodes] = useState([]);

  useEffect(() => {
    const map = new mapboxgl.Map({
      container: 'map-container',
      style: 'mapbox://styles/mapbox/dark-v11',
      center: [-75.1652, 39.9526],
      zoom: 12
    });

    fetch('http://localhost:8080/nearby?lat=39.9526&lon=-75.1652')
      .then(res => res.json())
      .then(data => {
        const matches = data.nodes || [];
        setNodes(matches);
        matches.forEach(node => {
          const lat = node.location?.latitude || node.lat;
          const lon = node.location?.longitude || node.lon;
          if (lat && lon) {
            new mapboxgl.Marker({ color: 'red' })
              .setLngLat([lon, lat])
              .setPopup(new mapboxgl.Popup().setHTML(`<b>SIGINT DETECTED</b><br/>${node.ip_str || node.label}`))
              .addTo(map);
          }
        });
      });

    return () => map.remove();
  }, []);

  return (
    <div className="window" style={{ width: '100vw', height: '100vh', display: 'flex', flexDirection: 'column' }}>
      <div className="title-bar">
        <div className="title-bar-text">GRIDLAND TACTICAL - WIRETAPPER ACTIVE</div>
      </div>
      <div className="window-body" style={{ flex: 1, position: 'relative', margin: 0 }}>
        <div id="map-container" style={{ width: '100%', height: '100%' }} />
        <div className="status-bar" style={{ position: 'absolute', bottom: 0, width: '100%', background: '#c0c0c0', color: 'black', padding: '2px 5px' }}>
          <p className="status-bar-field">NODES DETECTED: {nodes.length}</p>
        </div>
      </div>
    </div>
  );
}

export default App;
