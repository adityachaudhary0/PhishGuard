def tld_bucket(tld):

  high_trust  = {'.com', '.org', '.edu', '.gov', '.net', '.co.uk', '.ac.uk'}
  medium_trust = {'.io', '.co', '.me', '.uk', '.de', '.fr', '.in', '.ca', '.au'}
  low_trust   = {'.xyz', '.top', '.click', '.online', '.site', '.info', '.biz'}
  very_low    = {'.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc'}
  if tld in high_trust:   return 4
  if tld in medium_trust: return 3
  if tld in low_trust:    return 2
  if tld in very_low:     return 1
  return 0