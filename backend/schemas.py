# ============================================================
# schemas.py - CICIDS-2017
# Modele Pydantic pour la validation des donnees entrantes
# 20 features selectionnees par Random Forest sur CICIDS-2017
# ============================================================

from pydantic import BaseModel
from typing   import Optional


class NetworkData(BaseModel):
    # ── TOP 20 FEATURES CICIDS-2017 ─────────────────────────
    packet_length_std:            float = 0.0
    packet_length_max:            float = 0.0
    rst_flag_count:               float = 0.0
    fwd_packet_length_max:        float = 0.0
    total_length_of_fwd_packet:   float = 0.0
    fwd_packet_length_mean:       float = 0.0
    bwd_packet_length_std:        float = 0.0
    packet_length_mean:           float = 0.0
    subflow_fwd_bytes:            float = 0.0
    flow_iat_max:                 float = 0.0
    bwd_packet_length_mean:       float = 0.0
    bwd_packet_length_max:        float = 0.0
    packet_length_variance:       float = 0.0
    dst_port:                     float = 0.0
    bwd_segment_size_avg:         float = 0.0
    bwd_psh_flags:                float = 0.0
    flow_bytes_s:                 float = 0.0
    flow_packets_s:               float = 0.0
    average_packet_size:          float = 0.0
    fwd_segment_size_avg:         float = 0.0

    # ── Modele selectionne ───────────────────────────────────
    model: Optional[str] = "random_forest"
