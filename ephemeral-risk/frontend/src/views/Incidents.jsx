import { useState, useCallback } from 'react';
import IncidentCard from '../components/IncidentCard';
import IncidentDetailModal from '../components/IncidentDetailModal';
import AnimatedList from '../components/ui/AnimatedList';

export default function Incidents({ appState }) {
  const { incidents, authFetch, addToast, logAction } = appState;

  const [modalOpen, setModalOpen] = useState(false);
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [selectedIncident, setSelectedIncident] = useState(null);

  const handleDrillDown = useCallback((incidentId) => {
    // find the seed incident from the current list so the modal has data instantly
    const seed = incidents.find(i => i.incident_id === incidentId) || null;
    setSelectedIncidentId(incidentId);
    setSelectedIncident(seed);
    setModalOpen(true);
  }, [incidents]);

  const handleCloseModal = useCallback(() => {
    setModalOpen(false);
    setSelectedIncidentId(null);
    setSelectedIncident(null);
  }, []);

  return (
    <div className="page-view" id="view-incidents">
      <div className="page-header" style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <div className="breadcrumb"></div>
          <h2>Prioritised Incident Queue</h2>
          <p>Risk-ranked correlated campaigns</p>
        </div>
        <span className="badge badge-red">{incidents.length} prioritised</span>
      </div>



      <div id="incident-queue" style={{display:'flex', flexDirection:'column', gap:'16px'}}>
        {incidents.length === 0 ? (
          <div className="empty-state">
            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth="1.5"><path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
            <p>No correlated campaigns detected</p>
            <small>The detection engine is continuously analysing raw telemetry.</small>
          </div>
        ) : (
          <AnimatedList
            items={incidents}
            renderItem={(inc, i, isSelected) => (
              <div style={{ marginBottom: '16px' }}>
                <IncidentCard key={inc.incident_id} inc={inc} idx={i} authFetch={authFetch} addToast={addToast} logAction={logAction} onDrillDown={handleDrillDown} />
              </div>
            )}
          />
        )}
      </div>

      <IncidentDetailModal
        isOpen={modalOpen}
        incidentId={selectedIncidentId}
        incidentSeed={selectedIncident}
        authFetch={authFetch}
        addToast={addToast}
        logAction={logAction}
        onClose={handleCloseModal}
      />
    </div>
  );
}
