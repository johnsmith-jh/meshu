export const hex = (b: Uint8Array): string =>
  Array.from(b)
    .map(x => x.toString(16).padStart(2, '0'))
    .join('');
