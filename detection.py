# detection.py
import numpy as np
from typing import List, Dict
import time

def cosine(a, b):
    a = np.array(a, dtype=float)
    b = np.array(b, dtype=float)
    if a.size == 0 or b.size == 0:
        return 0.0
    denom = (np.linalg.norm(a) * np.linalg.norm(b))
    if denom == 0:
        return 0.0
    return float(np.dot(a, b) / denom)

def dna_similarity(profile_a: Dict, profile_b: Dict) -> float:
    t_sim = cosine(profile_a.get('typing', []), profile_b.get('typing', []))
    m_sim = cosine(profile_a.get('mouse', []), profile_b.get('mouse', []))
    return 0.6 * t_sim + 0.4 * m_sim

def compute_risk(fp_rows: List[Dict],
                 known_dna_profiles: List[Dict],
                 ip_info: Dict,
                 honeypot_triggered: bool,
                 account_age_days: int,
                 social_scores: Dict = None) -> Dict:

    score = 0
    reasons = []
    dna_matches = []

    if fp_rows and len(fp_rows) > 1:
        extra = min(40, 10 * (len(fp_rows) - 1))
        score += extra
        reasons.append(f'Duplicate fingerprint: {len(fp_rows)} previous hits (+{extra})')

    if ip_info.get('is_datacenter'):
        score += 25
        reasons.append('Datacenter ASN detected (+25)')
    if ip_info.get('is_vpn'):
        score += 30
        reasons.append('VPN/Tor/proxy detected (+30)')

    if honeypot_triggered:
        score += 80
        reasons.append('Honeypot element interacted (automation) (+80)')

    if account_age_days < 7:
        add = 10
        score += add
        reasons.append(f'New Discord account (<7d) (+{add})')

    if social_scores:
        iso = social_scores.get('is_isolated', False)
        if iso:
            score += 5
            reasons.append('Account has no strong social graph (isolated) (+5)')
        else:
            score -= 5
            reasons.append('Account connected to known trusted members (-5)')

    current_profile = None
    if fp_rows:
        try:
            # our demo stores dna inside fp JSON if available
            import json
            fp_json = fp_rows[0][2] if len(fp_rows[0])>2 else None
            parsed = json.loads(fp_json) if fp_json else {}
            current_profile = parsed.get('dna')
        except Exception:
            current_profile = None

    if current_profile:
        for prof in known_dna_profiles:
            sim = dna_similarity(current_profile, prof)
            if sim > 0.80:
                dna_matches.append({'discord_id': prof.get('discord_id'), 'sim': round(sim, 3)})
                score += 35
                reasons.append(f'DNA similarity to {prof.get("discord_id")} (sim={sim:.2f}) (+35)')

    final = max(0, min(100, int(score)))
    return {'risk_score': final, 'reasons': reasons, 'dna_matches': dna_matches, 'computed_at': int(time.time())}
