from pydantic import BaseModel

class TrafficData(BaseModel):
    id_orig_p: float = 0.0           # Port source
    id_resp_p: float = 80.0          # Port destination
    duration: float = 0.0            # Durée connexion
    orig_bytes: float = 0.0          # Octets envoyés
    resp_bytes: float = 0.0          # Octets reçus
    missed_bytes: float = 0.0        # Octets perdus
    orig_pkts: float = 1.0           # Paquets envoyés
    orig_ip_bytes: float = 0.0       # Octets IP source
    resp_pkts: float = 1.0           # Paquets reçus
    resp_ip_bytes: float = 0.0       # Octets IP destination
    is_orig_local: int = 1           # IP locale (1) ou externe (0)
    orig_h_count: float = 1.0        # Fréquence IP source
    resp_h_count: float = 1.0        # Fréquence IP destination
    is_well_known_port: int = 0      # Port < 1024
    hour: int = 12                   # Heure
    minute: int = 0                  # Minute
    day_of_week: int = 0             # Jour (0=lundi)
    inter_arrival_time: float = 0.0  # Intervalle entre connexions
    pkt_ratio: float = 1.0           # Ratio paquets
    avg_orig_pkt_size: float = 0.0   # Taille moyenne paquets source
    avg_resp_pkt_size: float = 0.0   # Taille moyenne paquets destination
    model: str = "random_forest"     # Modele ML selectionne

class PredictionResult(BaseModel):
    prediction: int
    label: str
    confidence: float
    risk_level: str
    model_used: str
    alert_message: str
