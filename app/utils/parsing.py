
def parse_activation_log(script_name: str):
    """Parse MikroMan activation log script name.
    
    Format: date-|-time-|-user-|-price-|-address-|-mac-|-validity-|-profile-|-comment
    Index:    0     1      2      3       4         5     6          7         8
    """
    try:
        parts = (script_name or '').split('-|-')
        if len(parts) >= 8:
            # parts[3] = price (selling price from on-login script)
            try:
                price_val = float(parts[3])
            except (ValueError, TypeError):
                price_val = 0.0
            return {
                'date': parts[0].strip(),
                'time': parts[1].strip(),
                'username': parts[2].strip(),
                'price': price_val,
                'ip': parts[4].strip() if len(parts) > 4 else '',
                'mac': parts[5].strip() if len(parts) > 5 else '',
                'validity': parts[6].strip() if len(parts) > 6 else '',
                'profile': parts[7].strip() if len(parts) > 7 else '',
                'comment': parts[8].strip() if len(parts) > 8 else '',
            }
    except Exception:
        return None
    return None
