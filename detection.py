# detection.py
"""
Upgraded risk engine inspired by Double Counter premium features.
Synchronous computation: expects ip_info (dict) to already contain
results from IP intelligence (is_vpn, is_tor, proxy_score, asn, is_datacenter).
"""

from typing import List, Dict
import numpy as np

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
                 social_scores: Dict = None,
                 db_stats: Dict = None) -> Dict:
    """
    db_stats: optional dict containing:
      - same_ip_count: int
      - same_fp_count: int
      - previously_banned_count: int
    """
    score = 0.0
    reasons = []
    dna_matches = []

    # Premium weights (tuneable)
    W_DUP_FP = 25.0
    W_DUP_IP = 20.0
    W_ASN_DATACENTER = 25.0
    W_VPN = 35.0
    W_TOR = 40.0
    W_PROXY_SCORE_FACTOR = 0.5  # multiply proxy_score (0-100) by this
    W_HONEYPOT = 90.0
    W_ACCOUNT_AGE = 20.0
    W_DNA_MATCH = 35.0
    W_PREVIOUS_BANS = 25.0
    W_SOCIAL_ISOLATION = 8.0

    # duplicate fingerprint (strong signal)
    if db_stats:
        if db_stats.get('same_fp_count', 0) > 0:
            delta = min(3, db_stats['same_fp_count'])  # scale
            add = W_DUP_FP * delta
            score += add
            reasons.append(f'Duplicate fingerprint matches {db_stats["same_fp_count"]} (+{add:.0f})')

        if db_stats.get('same_ip_count', 0) > 0:
            delta = min(4, db_stats['same_ip_count'])
            add = W_DUP_IP * (delta / 2.0)
            score += add
            reasons.append(f'Same IP seen across {db_stats["same_ip_count"]} accounts (+{add:.0f})')

        if db_stats.get('previously_banned_count', 0) > 0:
            add = min( W_PREVIOUS_BANS, db_stats['previously_banned_count'] * 10 )
            score += add
            reasons.append(f'Previously banned accounts on same device/IP (+{add:.0f})')

    # ip_info flags
    if ip_info:
        if ip_info.get('is_datacenter'):
            score += W_ASN_DATACENTER
            reasons.append(f'Datacenter ASN detected (+{W_ASN_DATACENTER})')
        if ip_info.get('is_vpn'):
            score += W_VPN
            reasons.append(f'VPN/proxy likely (+{W_VPN})')
        if ip_info.get('is_tor'):
            score += W_TOR
            reasons.append(f'Tor exit node detected (+{W_TOR})')
        proxy_score = ip_info.get('proxy_score')
        if proxy_score:
            add = proxy_score * W_PROXY_SCORE_FACTOR
            score += add
            reasons.append(f'Proxy score {proxy_score} (+{add:.1f})')

    # honeypot is nearly certain
    if honeypot_triggered:
        score += W_HONEYPOT
        reasons.append(f'Honeypot triggered (+{W_HONEYPOT})')

    # account age
    if account_age_days < 1:
        score += W_ACCOUNT_AGE
        reasons.append(f'New account (<1d) (+{W_ACCOUNT_AGE})')
    elif account_age_days < 7:
        score += W_ACCOUNT_AGE * 0.6
        reasons.append(f'New account (<7d) (+{W_ACCOUNT_AGE*0.6:.0f})')

    # DNA comparisons
    current_profile = None
    if fp_rows:
        current_profile = fp_rows[0].get('dna')
    if current_profile and known_dna_profiles:
        for prof in known_dna_profiles:
            # prof: {'discord_id','typing','mouse'}
            other_profile = {'typing': prof.get('typing', []), 'mouse': prof.get('mouse', [])}
            sim = dna_similarity(current_profile, other_profile)
            if sim > 0.78:
                dna_matches.append({'discord_id': prof.get('discord_id'), 'sim': round(sim, 3)})
                score += W_DNA_MATCH
                reasons.append(f'DNA match to {prof.get("discord_id")} sim={sim:.2f} (+{W_DNA_MATCH})')

    # social isolation
    if social_scores:
        if social_scores.get('is_isolated', False):
            score += W_SOCIAL_ISOLATION
            reasons.append(f'No social links (+{W_SOCIAL_ISOLATION})')
        else:
            reasons.append('Social links present (-8)')

    # normalize and bounds
    final = max(0, min(100, int(round(score))))
    return {
        'risk_score': final,
        'reasons': reasons,
        'dna_matches': dna_matches,
        'computed_at': int(__import__('time').time())
    }
