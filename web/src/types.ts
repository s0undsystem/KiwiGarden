// Shapes shared across modules. Everything that came from the relay is
// data, never markup: render only via textContent.

export interface Receiver {
  id: string;
  name: string;
  loc: string;
  antenna: string;
  version: string;
  lat: number;
  lon: number;
  users: number;
  usersMax: number;
  extApi: number; // -1 unknown, 0 disallows apps like us
  snr: number;
  offline: boolean;
}

export interface DirectoryResponse {
  fetchedAt: string;
  fromCache: boolean;
  receivers: Receiver[];
}

/** True when we could plausibly connect right now. */
export function isOpen(r: Receiver): boolean {
  return !r.offline && r.extApi !== 0 && r.users < r.usersMax;
}
