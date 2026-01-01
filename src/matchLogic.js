export function isCompatible(u1, u2) {
  // Basic compatibility logic: similar energy level or overlapping intentions
  const sameEnergy = u1.energyLevel === u2.energyLevel;
  const overlappingIntentions = u1.intentions.some(i => u2.intentions.includes(i));
  
  return sameEnergy || overlappingIntentions;
}

export function getMatchesForCurrentUser(currentUser, users) {
  return users.filter(
    u => u.id !== currentUser.id && isCompatible(currentUser, u)
  );
}
