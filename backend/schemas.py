from pydantic import BaseModel

class TrafficData(BaseModel):
    id_orig_p: float = 0.0
    id_resp_p: float = 80.0
    duration: float = 0.0
    orig_bytes: float = 0.0
    resp_bytes: float = 0.0
    missed_bytes: float = 0.0
    orig_pkts: float = 1.0
    orig_ip_bytes: float = 0.0
    resp_pkts: float = 1.0
    resp_ip_bytes: float = 0.0
    is_orig_local: int = 1
    orig_h_count: float = 1.0
    resp_h_count: float = 1.0
    is_well_known_port: int = 0
    hour: int = 12
    minute: int = 0
    day_of_week: int = 0
    inter_arrival_time: float = 0.0
    pkt_ratio: float = 1.0
    avg_orig_pkt_size: float = 0.0
    avg_resp_pkt_size: float = 0.0
    model: str = "random_forest"

class PredictionResult(BaseModel):
    prediction: int
    label: str
    confidence: float
    risk_level: str
    model_used: str
    alert_message: str
